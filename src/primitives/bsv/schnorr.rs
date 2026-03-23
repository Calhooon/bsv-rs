//! Schnorr zero-knowledge proofs for ECDH shared secret computation.
//!
//! This module implements Schnorr ZK proofs that demonstrate knowledge of a private key
//! and correct computation of an ECDH shared secret without revealing the private key.
//!
//! # Overview
//!
//! The Schnorr proof allows a prover to demonstrate:
//! 1. They know a private key `a` corresponding to public key `A = a*G`
//! 2. They correctly computed a shared secret `S = a*B` using another party's public key `B`
//!
//! This is useful for proving ECDH computation without revealing the private key.
//!
//! # Example
//!
//! ```rust
//! use bsv_rs::primitives::ec::PrivateKey;
//! use bsv_rs::primitives::bsv::schnorr::Schnorr;
//!
//! // Alice and Bob have key pairs
//! let alice = PrivateKey::random();
//! let bob = PrivateKey::random();
//!
//! // Alice computes shared secret with Bob's public key
//! let shared = alice.derive_shared_secret(&bob.public_key()).unwrap();
//!
//! // Alice generates a proof that she knows her private key and computed the shared secret correctly
//! let proof = Schnorr::generate_proof(
//!     &alice,
//!     &alice.public_key(),
//!     &bob.public_key(),
//!     &shared
//! ).unwrap();
//!
//! // Anyone can verify the proof without learning Alice's private key
//! assert!(Schnorr::verify_proof(
//!     &alice.public_key(),
//!     &bob.public_key(),
//!     &shared,
//!     &proof
//! ));
//! ```

use crate::error::Result;
use crate::primitives::ec::{PrivateKey, PublicKey};
use crate::primitives::hash::sha256;
use crate::primitives::BigNumber;

/// A Schnorr zero-knowledge proof.
///
/// This proof demonstrates knowledge of a private key and correct computation
/// of an ECDH shared secret without revealing the private key.
///
/// The proof consists of:
/// - `r`: The commitment point R = r*G where r is a random nonce
/// - `s_prime`: The blinded shared secret S' = r*B
/// - `z`: The response z = r + e*a mod n where e is the challenge
#[derive(Clone, Debug)]
pub struct SchnorrProof {
    /// R = r*G where r is the random nonce
    pub r: PublicKey,
    /// S' = r*B (blinded shared secret)
    pub s_prime: PublicKey,
    /// z = r + e*a mod n (response)
    pub z: BigNumber,
}

/// Schnorr ZK proof generation and verification.
pub struct Schnorr;

impl Schnorr {
    /// Generates a Schnorr proof demonstrating knowledge of private key `a`
    /// and correct computation of shared secret `S = a*B`.
    ///
    /// # Algorithm
    ///
    /// 1. Generate random nonce `r`
    /// 2. Compute `R = r*G`
    /// 3. Compute `S' = r*B`
    /// 4. Compute challenge `e = H(A || B || S || S' || R) mod n`
    /// 5. Compute `z = r + e*a mod n`
    /// 6. Return `(R, S', z)`
    ///
    /// # Arguments
    ///
    /// * `a` - The prover's private key
    /// * `big_a` - The prover's public key (should equal a*G)
    /// * `big_b` - The other party's public key
    /// * `big_s` - The shared secret (should equal a*B)
    ///
    /// # Returns
    ///
    /// A Schnorr proof that can be verified without revealing the private key
    pub fn generate_proof(
        a: &PrivateKey,
        big_a: &PublicKey,
        big_b: &PublicKey,
        big_s: &PublicKey,
    ) -> Result<SchnorrProof> {
        // Generate random nonce r
        let r = PrivateKey::random();

        // R = r*G (public key from nonce)
        let big_r = r.public_key();

        // S' = r*B (blinded shared secret)
        let s_prime = big_b.mul_scalar(&r.to_bytes())?;

        // e = H(A || B || S || S' || R) mod n
        let e = Self::compute_challenge(big_a, big_b, big_s, &s_prime, &big_r);

        // z = r + e*a mod n
        let order = BigNumber::secp256k1_order();
        let r_bn = BigNumber::from_bytes_be(&r.to_bytes());
        let a_bn = BigNumber::from_bytes_be(&a.to_bytes());
        let z = r_bn.add(&e.mul(&a_bn)).modulo(&order);

        Ok(SchnorrProof {
            r: big_r,
            s_prime,
            z,
        })
    }

    /// Verifies a Schnorr proof.
    ///
    /// # Algorithm
    ///
    /// 1. Recompute challenge `e = H(A || B || S || S' || R) mod n`
    /// 2. Verify: `z*G == R + e*A`
    /// 3. Verify: `z*B == S' + e*S`
    ///
    /// # Arguments
    ///
    /// * `big_a` - The prover's public key
    /// * `big_b` - The other party's public key
    /// * `big_s` - The claimed shared secret
    /// * `proof` - The Schnorr proof to verify
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify_proof(
        big_a: &PublicKey,
        big_b: &PublicKey,
        big_s: &PublicKey,
        proof: &SchnorrProof,
    ) -> bool {
        // Recompute challenge e = H(A || B || S || S' || R) mod n
        let e = Self::compute_challenge(big_a, big_b, big_s, &proof.s_prime, &proof.r);
        let e_bytes = e.to_bytes_be(32);
        let e_bytes_arr: [u8; 32] = e_bytes.try_into().expect("e should be 32 bytes");

        let z_bytes = proof.z.to_bytes_be(32);
        let z_bytes_arr: [u8; 32] = z_bytes.try_into().expect("z should be 32 bytes");

        // Check: z*G == R + e*A
        let z_g = match PublicKey::from_scalar_mul_generator(&z_bytes_arr) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let e_a = match big_a.mul_scalar(&e_bytes_arr) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let r_plus_ea = match proof.r.add(&e_a) {
            Ok(p) => p,
            Err(_) => return false,
        };
        if z_g != r_plus_ea {
            return false;
        }

        // Check: z*B == S' + e*S
        let z_b = match big_b.mul_scalar(&z_bytes_arr) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let e_s = match big_s.mul_scalar(&e_bytes_arr) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let s_prime_plus_es = match proof.s_prime.add(&e_s) {
            Ok(p) => p,
            Err(_) => return false,
        };

        z_b == s_prime_plus_es
    }

    /// Computes the Fiat-Shamir challenge.
    ///
    /// `e = SHA256(A || B || S || S' || R) mod n`
    ///
    /// All points are serialized in compressed format (33 bytes each).
    fn compute_challenge(
        a: &PublicKey,
        b: &PublicKey,
        s: &PublicKey,
        s_prime: &PublicKey,
        r: &PublicKey,
    ) -> BigNumber {
        // Concatenate all points in compressed format
        let mut msg = Vec::with_capacity(33 * 5);
        msg.extend_from_slice(&a.to_compressed());
        msg.extend_from_slice(&b.to_compressed());
        msg.extend_from_slice(&s.to_compressed());
        msg.extend_from_slice(&s_prime.to_compressed());
        msg.extend_from_slice(&r.to_compressed());

        // Hash the concatenated points
        let hash = sha256(&msg);

        // Convert hash to BigNumber and reduce modulo curve order
        BigNumber::from_bytes_be(&hash).modulo(&BigNumber::secp256k1_order())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr_roundtrip() {
        let alice = PrivateKey::random();
        let bob = PrivateKey::random();
        let shared = alice.derive_shared_secret(&bob.public_key()).unwrap();

        let proof =
            Schnorr::generate_proof(&alice, &alice.public_key(), &bob.public_key(), &shared)
                .unwrap();

        assert!(Schnorr::verify_proof(
            &alice.public_key(),
            &bob.public_key(),
            &shared,
            &proof
        ));
    }

    #[test]
    fn test_schnorr_wrong_secret_fails() {
        let alice = PrivateKey::random();
        let bob = PrivateKey::random();
        let shared = alice.derive_shared_secret(&bob.public_key()).unwrap();

        // Generate proof with correct shared secret
        let proof =
            Schnorr::generate_proof(&alice, &alice.public_key(), &bob.public_key(), &shared)
                .unwrap();

        // Create a different (wrong) shared secret
        let carol = PrivateKey::random();
        let wrong_shared = alice.derive_shared_secret(&carol.public_key()).unwrap();

        // Verification should fail with wrong shared secret
        assert!(!Schnorr::verify_proof(
            &alice.public_key(),
            &bob.public_key(),
            &wrong_shared,
            &proof
        ));
    }

    #[test]
    fn test_schnorr_wrong_public_key_fails() {
        let alice = PrivateKey::random();
        let bob = PrivateKey::random();
        let shared = alice.derive_shared_secret(&bob.public_key()).unwrap();

        let proof =
            Schnorr::generate_proof(&alice, &alice.public_key(), &bob.public_key(), &shared)
                .unwrap();

        // Verification should fail with wrong prover public key
        let wrong_pubkey = PrivateKey::random().public_key();
        assert!(!Schnorr::verify_proof(
            &wrong_pubkey,
            &bob.public_key(),
            &shared,
            &proof
        ));
    }

    #[test]
    fn test_schnorr_wrong_bob_pubkey_fails() {
        let alice = PrivateKey::random();
        let bob = PrivateKey::random();
        let shared = alice.derive_shared_secret(&bob.public_key()).unwrap();

        let proof =
            Schnorr::generate_proof(&alice, &alice.public_key(), &bob.public_key(), &shared)
                .unwrap();

        // Verification should fail with wrong other party's public key
        let wrong_bob_pubkey = PrivateKey::random().public_key();
        assert!(!Schnorr::verify_proof(
            &alice.public_key(),
            &wrong_bob_pubkey,
            &shared,
            &proof
        ));
    }

    #[test]
    fn test_schnorr_mutual_verification() {
        // Both parties can generate proofs for the same shared secret
        let alice = PrivateKey::random();
        let bob = PrivateKey::random();

        // Alice computes shared secret
        let alice_shared = alice.derive_shared_secret(&bob.public_key()).unwrap();

        // Bob computes the same shared secret
        let bob_shared = bob.derive_shared_secret(&alice.public_key()).unwrap();

        // Both arrive at the same shared secret
        assert_eq!(alice_shared.to_compressed(), bob_shared.to_compressed());

        // Alice's proof
        let alice_proof = Schnorr::generate_proof(
            &alice,
            &alice.public_key(),
            &bob.public_key(),
            &alice_shared,
        )
        .unwrap();

        // Bob's proof (note the roles are swapped)
        let bob_proof =
            Schnorr::generate_proof(&bob, &bob.public_key(), &alice.public_key(), &bob_shared)
                .unwrap();

        // Both proofs should verify
        assert!(Schnorr::verify_proof(
            &alice.public_key(),
            &bob.public_key(),
            &alice_shared,
            &alice_proof
        ));

        assert!(Schnorr::verify_proof(
            &bob.public_key(),
            &alice.public_key(),
            &bob_shared,
            &bob_proof
        ));
    }

    #[test]
    fn test_schnorr_deterministic_challenge() {
        // The challenge should be deterministic given the same inputs
        let alice = PrivateKey::random();
        let bob = PrivateKey::random();
        let shared = alice.derive_shared_secret(&bob.public_key()).unwrap();

        let nonce = PrivateKey::random();
        let r = nonce.public_key();
        let s_prime = bob.public_key().mul_scalar(&nonce.to_bytes()).unwrap();

        let e1 = Schnorr::compute_challenge(
            &alice.public_key(),
            &bob.public_key(),
            &shared,
            &s_prime,
            &r,
        );

        let e2 = Schnorr::compute_challenge(
            &alice.public_key(),
            &bob.public_key(),
            &shared,
            &s_prime,
            &r,
        );

        assert_eq!(e1, e2);
    }

    #[test]
    fn test_schnorr_challenge_changes_with_different_inputs() {
        let alice = PrivateKey::random();
        let bob = PrivateKey::random();
        let shared = alice.derive_shared_secret(&bob.public_key()).unwrap();

        let nonce1 = PrivateKey::random();
        let r1 = nonce1.public_key();
        let s_prime1 = bob.public_key().mul_scalar(&nonce1.to_bytes()).unwrap();

        let nonce2 = PrivateKey::random();
        let r2 = nonce2.public_key();
        let s_prime2 = bob.public_key().mul_scalar(&nonce2.to_bytes()).unwrap();

        let e1 = Schnorr::compute_challenge(
            &alice.public_key(),
            &bob.public_key(),
            &shared,
            &s_prime1,
            &r1,
        );

        let e2 = Schnorr::compute_challenge(
            &alice.public_key(),
            &bob.public_key(),
            &shared,
            &s_prime2,
            &r2,
        );

        // Different nonces should produce different challenges
        assert_ne!(e1, e2);
    }
}
