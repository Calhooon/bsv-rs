//! HMAC-DRBG (Deterministic Random Bit Generator)
//!
//! Implementation of HMAC-DRBG as specified in NIST SP 800-90A.
//! Used internally for RFC 6979 deterministic ECDSA signatures.
//!
//! # Security Notice
//!
//! This implementation is specifically designed for deterministic signature
//! generation and is NOT forward-secure. Do not use as a general-purpose RNG.

use crate::primitives::hash::{sha256_hmac, sha512_hmac};

/// HMAC-DRBG state for deterministic random generation
#[derive(Clone)]
pub struct HmacDrbg {
    k: Vec<u8>,
    v: Vec<u8>,
    hash_len: usize,
    use_sha512: bool,
}

impl HmacDrbg {
    /// Create new HMAC-DRBG with SHA-256 (default)
    ///
    /// # Arguments
    /// * `entropy` - Initial entropy (minimum 32 bytes recommended)
    /// * `nonce` - Nonce value (typically 16 bytes)
    /// * `personalization` - Optional personalization string
    ///
    /// # Example
    /// ```
    /// use bsv_rs::primitives::drbg::HmacDrbg;
    ///
    /// let entropy = [0u8; 32];
    /// let nonce = [0u8; 16];
    /// let mut drbg = HmacDrbg::new(&entropy, &nonce, &[]);
    /// let random_bytes = drbg.generate(32);
    /// ```
    pub fn new(entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Self {
        Self::new_with_hash(entropy, nonce, personalization, false)
    }

    /// Create new HMAC-DRBG with specified hash function
    ///
    /// # Arguments
    /// * `use_sha512` - If true, use SHA-512; otherwise SHA-256
    pub fn new_with_hash(
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
        use_sha512: bool,
    ) -> Self {
        let hash_len = if use_sha512 { 64 } else { 32 };

        // Initial K = 0x00 repeated hash_len times
        let k = vec![0x00u8; hash_len];
        // Initial V = 0x01 repeated hash_len times
        let v = vec![0x01u8; hash_len];

        let mut drbg = Self {
            k,
            v,
            hash_len,
            use_sha512,
        };

        // Seed material = entropy || nonce || personalization
        let mut seed_material =
            Vec::with_capacity(entropy.len() + nonce.len() + personalization.len());
        seed_material.extend_from_slice(entropy);
        seed_material.extend_from_slice(nonce);
        seed_material.extend_from_slice(personalization);

        drbg.update(Some(&seed_material));
        drbg
    }

    /// Update internal state (NIST SP 800-90A Section 10.1.2.2)
    fn update(&mut self, provided_data: Option<&[u8]>) {
        // Step 1: K = HMAC(K, V || 0x00 || provided_data)
        let mut input =
            Vec::with_capacity(self.hash_len + 1 + provided_data.map_or(0, |d| d.len()));
        input.extend_from_slice(&self.v);
        input.push(0x00);
        if let Some(data) = provided_data {
            input.extend_from_slice(data);
        }
        self.k = self.hmac(&self.k, &input);

        // Step 2: V = HMAC(K, V)
        self.v = self.hmac(&self.k, &self.v);

        // Step 3-6: If provided_data is not empty, update again with 0x01
        if let Some(data) = provided_data {
            if !data.is_empty() {
                let mut input = Vec::with_capacity(self.hash_len + 1 + data.len());
                input.extend_from_slice(&self.v);
                input.push(0x01);
                input.extend_from_slice(data);
                self.k = self.hmac(&self.k, &input);

                self.v = self.hmac(&self.k, &self.v);
            }
        }
    }

    /// Generate random bytes (NIST SP 800-90A Section 10.1.2.5)
    ///
    /// # Arguments
    /// * `num_bytes` - Number of random bytes to generate
    ///
    /// # Returns
    /// Vector of random bytes
    pub fn generate(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(num_bytes);

        // Generate output by repeatedly computing V = HMAC(K, V)
        while output.len() < num_bytes {
            self.v = self.hmac(&self.k, &self.v);
            output.extend_from_slice(&self.v);
        }

        output.truncate(num_bytes);

        // Update state after generation
        self.update(None);

        output
    }

    /// Reseed the DRBG with new entropy
    ///
    /// # Arguments
    /// * `entropy` - New entropy input
    /// * `additional_input` - Optional additional input
    pub fn reseed(&mut self, entropy: &[u8], additional_input: &[u8]) {
        let mut seed_material = Vec::with_capacity(entropy.len() + additional_input.len());
        seed_material.extend_from_slice(entropy);
        seed_material.extend_from_slice(additional_input);
        self.update(Some(&seed_material));
    }

    /// Compute HMAC with configured hash function
    fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        if self.use_sha512 {
            sha512_hmac(key, data).to_vec()
        } else {
            sha256_hmac(key, data).to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drbg_deterministic() {
        let entropy = b"test entropy value for testing";
        let nonce = b"nonce value";

        let mut drbg1 = HmacDrbg::new(entropy, nonce, &[]);
        let mut drbg2 = HmacDrbg::new(entropy, nonce, &[]);

        assert_eq!(drbg1.generate(64), drbg2.generate(64));
    }

    #[test]
    fn test_drbg_state_advances() {
        let mut drbg = HmacDrbg::new(b"entropy", b"nonce", &[]);

        let output1 = drbg.generate(32);
        let output2 = drbg.generate(32);

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_drbg_personalization_affects_output() {
        let entropy = b"entropy";
        let nonce = b"nonce";

        let mut drbg1 = HmacDrbg::new(entropy, nonce, b"personalization1");
        let mut drbg2 = HmacDrbg::new(entropy, nonce, b"personalization2");

        assert_ne!(drbg1.generate(32), drbg2.generate(32));
    }

    #[test]
    fn test_drbg_reseed() {
        let mut drbg1 = HmacDrbg::new(b"entropy", b"nonce", &[]);
        let mut drbg2 = HmacDrbg::new(b"entropy", b"nonce", &[]);

        let _ = drbg1.generate(32);
        let _ = drbg2.generate(32);

        drbg1.reseed(b"new entropy", &[]);

        assert_ne!(drbg1.generate(32), drbg2.generate(32));
    }
}
