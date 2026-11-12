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
use crate::primitives::bsv::shamir::is_base58_field;
use crate::primitives::encoding::{from_base58, to_base58};
use crate::primitives::BigNumber;

/// The longest point text, in UTF-16 code units (`ts-stack@edf6e03`
/// `Polynomial.ts:8`).
const MAX_POINT_STRING_LENGTH: usize = 129;

/// A point in a finite field, representing a share in Shamir's Secret Sharing.
///
/// Both coordinates are reduced modulo the secp256k1 field prime.
///
/// Its `Debug` shows `x` (the share's index) and redacts `y` (the share's
/// value); `Display` and [`to_point_string`](Self::to_point_string) are the
/// explicit conversions to the share's text.
#[derive(Clone, PartialEq, Eq)]
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

    /// Parses a point from its text, `base58(x).base58(y)`, as the
    /// reference's `PointInFiniteField.fromString` reads it (`ts-stack@edf6e03`
    /// `Polynomial.ts:32-49`): at most 129 characters, exactly two fields,
    /// each 1 to 64 base58 characters, and the point's own text again, so a
    /// leading `1` (other than zero's `1`) or a coordinate at or above p is
    /// refused. Every refusal is the reference's one sentence, never the
    /// text, which carries `y`: `Finite-field point must use a bounded
    /// canonical Base58 representation`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::bsv::polynomial::PointInFiniteField;
    ///
    /// let point = PointInFiniteField::from_string("2.3J").unwrap();
    /// assert!(PointInFiniteField::from_string("12.3J").is_err());
    /// ```
    pub fn from_string(s: &str) -> Result<Self> {
        let refused = || {
            Error::InvalidBase58(
                "Finite-field point must use a bounded canonical Base58 representation".into(),
            )
        };
        // JavaScript's `length`: UTF-16 code units, counted to the bound.
        if s.encode_utf16().take(MAX_POINT_STRING_LENGTH + 1).count() > MAX_POINT_STRING_LENGTH {
            return Err(refused());
        }
        let mut parts = s.splitn(3, '.');
        let (Some(x), Some(y), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(refused());
        };
        if !is_base58_field(x) || !is_base58_field(y) {
            return Err(refused());
        }
        let x = BigNumber::from_bytes_be(&from_base58(x).map_err(|_| refused())?);
        let y = BigNumber::from_bytes_be(&from_base58(y).map_err(|_| refused())?);
        let point = Self::new(x, y);
        if point.to_point_string() != s {
            return Err(refused());
        }
        Ok(point)
    }

    /// Converts the point to a string in the format "base58(x).base58(y)".
    /// Reveals the share's value, which `Debug` redacts.
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

impl std::fmt::Debug for PointInFiniteField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PointInFiniteField")
            .field("x", &self.x)
            .field("y", &format_args!("<redacted>"))
            .finish()
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
///
/// Its `Debug` shows the threshold and the point count, never a point.
#[derive(Clone)]
pub struct Polynomial {
    /// The points that define the polynomial.
    pub points: Vec<PointInFiniteField>,
    /// The threshold (degree + 1) of the polynomial.
    pub threshold: usize,
}

impl std::fmt::Debug for Polynomial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Polynomial")
            .field("points", &self.points.len())
            .field("threshold", &self.threshold)
            .finish_non_exhaustive()
    }
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
    /// All arithmetic is performed modulo the secp256k1 field prime, and the
    /// value is the one the reference's `valueAt` computes (`ts-stack@edf6e03`
    /// `Polynomial.ts:120-136`) wherever it answers. The reference inverts each
    /// `(x_i - x_j)`; this takes one modular inverse for the whole call (#880):
    /// each denominator `D_i = Π(j≠i) (x_i - x_j)` is multiplied out, the `D_i`
    /// are inverted together (Montgomery's batch inversion) and
    /// `term_i = y_i * N_i * D_i^-1` with `N_i = Π(j≠i) (x - x_j)`.
    ///
    /// The leading `min(points.len(), threshold)` points are used: none answers
    /// 0, one its `y` reduced; a point whose x repeats another used point's (a
    /// `D_i` of 0) contributes 0, as go-sdk's zero inverse does. The reference
    /// refuses those and unreduced coordinates (`:102-117`). It never panics.
    ///
    /// Not constant time (`BigNumber` is variable-time throughout). What
    /// holds: every inverse's input and the one data branch (`D_i == 0`) are
    /// functions of the x coordinates alone; a `y` enters only as a factor.
    ///
    /// # Arguments
    ///
    /// * `x` - The x value at which to evaluate the polynomial
    ///
    /// # Returns
    ///
    /// The y value of the polynomial at x, in `[0, p)`
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

        // Use only threshold points
        let used = &self.points[..std::cmp::min(self.points.len(), self.threshold)];
        let n = used.len();

        // The numerators N_i = Π(j≠i) (x - x_j) mod P, by the products of
        // the factors before i and after i (a zero factor needs no inverse).
        let factors: Vec<BigNumber> = used.iter().map(|pt| x.sub(&pt.x).modulo(&p)).collect();
        let mut numerators = Vec::with_capacity(n);
        let mut before = BigNumber::one();
        for factor in &factors {
            numerators.push(before.clone());
            before = before.mul(factor).modulo(&p);
        }
        let mut after = BigNumber::one();
        for (numerator, factor) in numerators.iter_mut().zip(&factors).rev() {
            *numerator = numerator.mul(&after).modulo(&p);
            after = after.mul(factor).modulo(&p);
        }

        // The denominators D_i = Π(j≠i) (x_i - x_j) mod P: of the x
        // coordinates alone. Zero exactly when x_i repeats among the points.
        let denominators: Vec<BigNumber> = (0..n)
            .map(|i| {
                let mut d = BigNumber::one();
                for j in (0..n).filter(|&j| j != i) {
                    d = d.mul(&used[i].x.sub(&used[j].x)).modulo(&p);
                }
                d
            })
            .collect();

        // One inverse for every non-zero D_i (Montgomery): the running
        // products, the inverse of the last, then the walk back. A zero is
        // never multiplied in (it would zero every inverse); its term is 0,
        // the value the per-pair zero inverse gave it.
        let mut running = Vec::with_capacity(n);
        let mut product = BigNumber::one();
        for d in denominators.iter().filter(|d| !d.is_zero()) {
            running.push(product.clone());
            product = product.mul(d).modulo(&p);
        }
        // P is prime and every factor is in [1, P): the inverse exists.
        let mut inverse_of_rest = product.mod_inverse(&p).unwrap_or_else(BigNumber::zero);

        let mut y = BigNumber::zero();
        for i in (0..n).rev() {
            let d = &denominators[i];
            if d.is_zero() {
                continue;
            }
            let Some(prefix) = running.pop() else {
                break; // unreachable: one prefix was pushed per non-zero D_i
            };
            let d_inverse = inverse_of_rest.mul(&prefix).modulo(&p);
            inverse_of_rest = inverse_of_rest.mul(d).modulo(&p);

            // term = y_i * N_i * D_i^-1 mod P; y = (y + term) mod P
            let weight = numerators[i].mul(&d_inverse).modulo(&p);
            y = y.add(&used[i].y.mul(&weight)).modulo(&p);
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
