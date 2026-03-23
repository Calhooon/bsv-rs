//! Polynomial operations for Shamir Secret Sharing.
//!
//! This module provides polynomial arithmetic over a finite field, specifically
//! for use in Shamir's Secret Sharing scheme. All operations are performed
//! modulo the secp256k1 field prime.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::primitives::bsv::polynomial::{PointInFiniteField, Polynomial};
//! use bsv_rs::primitives::BigNumber;
//!
//! // Create points from shares
//! let p1 = PointInFiniteField::new(BigNumber::from_u64(1), BigNumber::from_hex("abc123").unwrap());
//! let p2 = PointInFiniteField::new(BigNumber::from_u64(2), BigNumber::from_hex("def456").unwrap());
//! let p3 = PointInFiniteField::new(BigNumber::from_u64(3), BigNumber::from_hex("789abc").unwrap());
//!
//! // Create polynomial and evaluate at x=0 to recover secret
//! let poly = Polynomial::new(vec![p1, p2, p3], 3);
//! let secret = poly.value_at(&BigNumber::zero());
//! ```

use crate::error::{Error, Result};
use crate::primitives::encoding::{from_base58, to_base58};
use crate::primitives::BigNumber;

/// A point in a finite field, representing a share in Shamir's Secret Sharing.
///
/// Both coordinates are reduced modulo the secp256k1 field prime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PointInFiniteField {
    /// The x-coordinate of the point.
    pub x: BigNumber,
    /// The y-coordinate of the point.
    pub y: BigNumber,
}

impl PointInFiniteField {
    /// Creates a new point, reducing both coordinates modulo the secp256k1 field prime.
    ///
    /// # Arguments
    ///
    /// * `x` - The x-coordinate
    /// * `y` - The y-coordinate
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::bsv::polynomial::PointInFiniteField;
    /// use bsv_rs::primitives::BigNumber;
    ///
    /// let point = PointInFiniteField::new(
    ///     BigNumber::from_u64(1),
    ///     BigNumber::from_hex("abcdef").unwrap()
    /// );
    /// ```
    pub fn new(x: BigNumber, y: BigNumber) -> Self {
        let p = BigNumber::secp256k1_prime();
        Self {
            x: x.modulo(&p),
            y: y.modulo(&p),
        }
    }

    /// Parses a point from a string in the format "base58(x).base58(y)".
    ///
    /// # Arguments
    ///
    /// * `s` - The string representation of the point
    ///
    /// # Returns
    ///
    /// The parsed point, or an error if the format is invalid
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::bsv::polynomial::PointInFiniteField;
    ///
    /// let point = PointInFiniteField::from_string("2.3J").unwrap();
    /// ```
    pub fn from_string(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 2 {
            return Err(Error::InvalidBase58(format!(
                "Invalid point string format: expected 'base58(x).base58(y)', got '{}'",
                s
            )));
        }

        let x_bytes = from_base58(parts[0])?;
        let y_bytes = from_base58(parts[1])?;

        let x = BigNumber::from_bytes_be(&x_bytes);
        let y = BigNumber::from_bytes_be(&y_bytes);

        Ok(Self::new(x, y))
    }

    /// Converts the point to a string in the format "base58(x).base58(y)".
    ///
    /// # Returns
    ///
    /// A string representation of the point
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::bsv::polynomial::PointInFiniteField;
    /// use bsv_rs::primitives::BigNumber;
    ///
    /// let point = PointInFiniteField::new(
    ///     BigNumber::from_u64(1),
    ///     BigNumber::from_u64(100)
    /// );
    /// let s = point.to_string();
    /// ```
    pub fn to_point_string(&self) -> String {
        // Get minimal byte representations
        let x_bytes = self.x.to_bytes_be_min();
        let y_bytes = self.y.to_bytes_be_min();

        // Handle zero values - base58 of empty is empty, but we need "1" for zero
        let x_str = if x_bytes.is_empty() {
            "1".to_string() // base58 encoding of [0x00]
        } else {
            to_base58(&x_bytes)
        };

        let y_str = if y_bytes.is_empty() {
            "1".to_string()
        } else {
            to_base58(&y_bytes)
        };

        format!("{}.{}", x_str, y_str)
    }
}

impl std::fmt::Display for PointInFiniteField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_point_string())
    }
}

/// A polynomial over a finite field, used for Lagrange interpolation.
///
/// Given a set of points, this structure can evaluate the unique polynomial
/// of degree (threshold - 1) that passes through those points.
#[derive(Clone, Debug)]
pub struct Polynomial {
    /// The points that define the polynomial.
    pub points: Vec<PointInFiniteField>,
    /// The threshold (degree + 1) of the polynomial.
    pub threshold: usize,
}

impl Polynomial {
    /// Creates a new polynomial from a set of points.
    ///
    /// # Arguments
    ///
    /// * `points` - The points that define the polynomial
    /// * `threshold` - The minimum number of points needed for interpolation
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::bsv::polynomial::{PointInFiniteField, Polynomial};
    /// use bsv_rs::primitives::BigNumber;
    ///
    /// let points = vec![
    ///     PointInFiniteField::new(BigNumber::from_u64(1), BigNumber::from_u64(10)),
    ///     PointInFiniteField::new(BigNumber::from_u64(2), BigNumber::from_u64(20)),
    /// ];
    /// let poly = Polynomial::new(points, 2);
    /// ```
    pub fn new(points: Vec<PointInFiniteField>, threshold: usize) -> Self {
        Self { points, threshold }
    }

    /// Evaluates the polynomial at a given x value using Lagrange interpolation.
    ///
    /// The formula is:
    /// ```text
    /// y = Σ(i=0 to t-1) y_i * Π(j≠i) (x - x_j) / (x_i - x_j)
    /// ```
    ///
    /// All arithmetic is performed modulo the secp256k1 field prime.
    ///
    /// # Arguments
    ///
    /// * `x` - The x value at which to evaluate the polynomial
    ///
    /// # Returns
    ///
    /// The y value of the polynomial at x
    ///
    /// # Panics
    ///
    /// Panics if there are fewer points than the threshold or if the modular
    /// inverse cannot be computed (which indicates duplicate x coordinates).
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::bsv::polynomial::{PointInFiniteField, Polynomial};
    /// use bsv_rs::primitives::BigNumber;
    ///
    /// // A simple linear polynomial passing through (1, 1) and (2, 2)
    /// let points = vec![
    ///     PointInFiniteField::new(BigNumber::from_u64(1), BigNumber::from_u64(1)),
    ///     PointInFiniteField::new(BigNumber::from_u64(2), BigNumber::from_u64(2)),
    /// ];
    /// let poly = Polynomial::new(points, 2);
    ///
    /// // Evaluate at x=0 should give y=0 (the y-intercept)
    /// let y = poly.value_at(&BigNumber::zero());
    /// assert_eq!(y, BigNumber::zero());
    /// ```
    pub fn value_at(&self, x: &BigNumber) -> BigNumber {
        let p = BigNumber::secp256k1_prime();
        let mut y = BigNumber::zero();

        // Use only threshold points
        let num_points = std::cmp::min(self.points.len(), self.threshold);

        for i in 0..num_points {
            let mut term = self.points[i].y.clone();

            for j in 0..num_points {
                if i != j {
                    // numerator = (x - x_j) mod P
                    let numerator = x.sub(&self.points[j].x).modulo(&p);

                    // denominator = (x_i - x_j) mod P
                    let denominator = self.points[i].x.sub(&self.points[j].x).modulo(&p);

                    // denominatorInv = denominator^(-1) mod P
                    let denominator_inv = denominator.mod_inverse(&p).unwrap_or_else(|| {
                        // This should never happen with valid, unique x coordinates
                        // But match the Go SDK behavior of returning 0
                        BigNumber::zero()
                    });

                    // fraction = numerator * denominatorInv mod P
                    let fraction = numerator.mul(&denominator_inv).modulo(&p);

                    // term = term * fraction mod P
                    term = term.mul(&fraction).modulo(&p);
                }
            }

            // y = (y + term) mod P
            y = y.add(&term).modulo(&p);
        }

        y
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_point_in_finite_field_new() {
        let p = BigNumber::secp256k1_prime();

        // Normal values
        let point = PointInFiniteField::new(BigNumber::from_u64(1), BigNumber::from_u64(2));
        assert_eq!(point.x, BigNumber::from_u64(1));
        assert_eq!(point.y, BigNumber::from_u64(2));

        // Values larger than prime should be reduced
        let large_x = p.add(&BigNumber::from_u64(5));
        let point = PointInFiniteField::new(large_x, BigNumber::from_u64(2));
        assert_eq!(point.x, BigNumber::from_u64(5));
    }

    #[test]
    fn test_point_in_finite_field_string_roundtrip() {
        let point = PointInFiniteField::new(BigNumber::from_u64(12345), BigNumber::from_u64(67890));

        let s = point.to_point_string();
        let parsed = PointInFiniteField::from_string(&s).unwrap();

        assert_eq!(point, parsed);
    }

    #[test]
    fn test_point_in_finite_field_from_string() {
        // Create a point, convert to string, then parse back
        let original =
            PointInFiniteField::new(BigNumber::from_u64(12345), BigNumber::from_u64(67890));
        let s = original.to_point_string();
        let parsed = PointInFiniteField::from_string(&s).unwrap();
        assert_eq!(parsed.x, BigNumber::from_u64(12345));
        assert_eq!(parsed.y, BigNumber::from_u64(67890));
    }

    #[test]
    fn test_point_in_finite_field_invalid_format() {
        // Missing separator
        assert!(PointInFiniteField::from_string("abc").is_err());

        // Too many parts
        assert!(PointInFiniteField::from_string("a.b.c").is_err());
    }

    #[test]
    fn test_polynomial_linear() {
        // Test with a simple linear polynomial: f(x) = 3x + 5
        // f(0) = 5, f(1) = 8, f(2) = 11
        let p5 = BigNumber::from_u64(5);
        let p8 = BigNumber::from_u64(8);

        let points = vec![
            PointInFiniteField::new(BigNumber::from_u64(1), p8.clone()),
            PointInFiniteField::new(BigNumber::from_u64(2), BigNumber::from_u64(11)),
        ];

        let poly = Polynomial::new(points, 2);

        // Evaluate at x=0 should give 5
        let y0 = poly.value_at(&BigNumber::zero());
        assert_eq!(y0, p5);

        // Evaluate at x=1 should give 8
        let y1 = poly.value_at(&BigNumber::from_u64(1));
        assert_eq!(y1, p8);
    }

    #[test]
    fn test_polynomial_quadratic() {
        // Test with a quadratic polynomial: f(x) = x^2 + 2x + 3
        // f(0) = 3, f(1) = 6, f(2) = 11, f(3) = 18

        let points = vec![
            PointInFiniteField::new(BigNumber::from_u64(1), BigNumber::from_u64(6)),
            PointInFiniteField::new(BigNumber::from_u64(2), BigNumber::from_u64(11)),
            PointInFiniteField::new(BigNumber::from_u64(3), BigNumber::from_u64(18)),
        ];

        let poly = Polynomial::new(points, 3);

        // Evaluate at x=0 should give 3
        let y0 = poly.value_at(&BigNumber::zero());
        assert_eq!(y0, BigNumber::from_u64(3));
    }

    #[test]
    fn test_polynomial_with_large_numbers() {
        // Test with numbers close to the field size
        let p = BigNumber::secp256k1_prime();

        // Create a simple linear polynomial with large y values
        let y1 = p.sub(&BigNumber::from_u64(10)); // p - 10
        let y2 = p.sub(&BigNumber::from_u64(5)); // p - 5

        let points = vec![
            PointInFiniteField::new(BigNumber::from_u64(1), y1),
            PointInFiniteField::new(BigNumber::from_u64(2), y2),
        ];

        let poly = Polynomial::new(points, 2);

        // The polynomial should evaluate correctly even with large numbers
        let y0 = poly.value_at(&BigNumber::zero());

        // For f(1) = p-10, f(2) = p-5, the slope is 5
        // f(x) = 5x + c, where c = p-15
        // f(0) = p - 15, which is equivalent to -15 mod p
        let expected = p.sub(&BigNumber::from_u64(15));
        assert_eq!(y0, expected);
    }

    #[test]
    fn test_polynomial_constant() {
        // A constant polynomial (threshold = 1) - just returns the y value
        let secret = BigNumber::from_hex("deadbeef").unwrap();

        let points = vec![PointInFiniteField::new(
            BigNumber::from_u64(1),
            secret.clone(),
        )];

        let poly = Polynomial::new(points, 1);

        // Evaluate at x=0 should give the same secret
        let y0 = poly.value_at(&BigNumber::zero());
        assert_eq!(y0, secret);
    }
}
