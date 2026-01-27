//! BIP-39 Mnemonic implementation.

use crate::primitives::hash::{pbkdf2_sha512, sha256};
use crate::{Error, Result};

use super::wordlists;

/// Supported word counts for BIP-39 mnemonics.
///
/// Each word count corresponds to a specific entropy size:
/// - 12 words = 128 bits entropy
/// - 15 words = 160 bits entropy
/// - 18 words = 192 bits entropy
/// - 21 words = 224 bits entropy
/// - 24 words = 256 bits entropy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordCount {
    /// 12-word mnemonic (128 bits entropy)
    Words12,
    /// 15-word mnemonic (160 bits entropy)
    Words15,
    /// 18-word mnemonic (192 bits entropy)
    Words18,
    /// 21-word mnemonic (224 bits entropy)
    Words21,
    /// 24-word mnemonic (256 bits entropy)
    Words24,
}

impl WordCount {
    /// Returns the entropy size in bytes for this word count.
    pub fn entropy_bytes(self) -> usize {
        match self {
            WordCount::Words12 => 16, // 128 bits
            WordCount::Words15 => 20, // 160 bits
            WordCount::Words18 => 24, // 192 bits
            WordCount::Words21 => 28, // 224 bits
            WordCount::Words24 => 32, // 256 bits
        }
    }

    /// Returns the number of words for this word count.
    pub fn word_count(self) -> usize {
        match self {
            WordCount::Words12 => 12,
            WordCount::Words15 => 15,
            WordCount::Words18 => 18,
            WordCount::Words21 => 21,
            WordCount::Words24 => 24,
        }
    }

    /// Returns the checksum size in bits for this word count.
    pub fn checksum_bits(self) -> usize {
        self.entropy_bytes() * 8 / 32
    }
}

/// Supported languages for BIP-39 wordlists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Language {
    /// English wordlist (default)
    #[default]
    English,
}

impl Language {
    /// Returns the wordlist for this language.
    fn wordlist(&self) -> &'static [&'static str; 2048] {
        match self {
            Language::English => &wordlists::ENGLISH,
        }
    }

    /// Returns the word separator for this language.
    fn separator(&self) -> &'static str {
        match self {
            Language::English => " ",
        }
    }

    /// Finds the index of a word in the wordlist.
    fn word_index(&self, word: &str) -> Option<usize> {
        let wordlist = self.wordlist();
        wordlist.iter().position(|&w| w == word)
    }
}

/// A BIP-39 mnemonic phrase.
///
/// This struct represents a validated mnemonic phrase that can be used to
/// generate deterministic seeds for wallet derivation.
#[derive(Debug, Clone)]
pub struct Mnemonic {
    /// The individual words of the mnemonic.
    words: Vec<String>,
    /// The language of the mnemonic.
    language: Language,
}

impl Mnemonic {
    /// Generates a new random mnemonic with the specified word count.
    ///
    /// # Arguments
    ///
    /// * `word_count` - The number of words in the mnemonic
    ///
    /// # Returns
    ///
    /// A new `Mnemonic` instance with random entropy.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::compat::bip39::{Mnemonic, WordCount};
    ///
    /// let mnemonic = Mnemonic::new(WordCount::Words12).unwrap();
    /// assert_eq!(mnemonic.words().len(), 12);
    /// ```
    pub fn new(word_count: WordCount) -> Result<Self> {
        let entropy_len = word_count.entropy_bytes();
        let mut entropy = vec![0u8; entropy_len];
        getrandom::getrandom(&mut entropy)
            .map_err(|e| Error::CryptoError(format!("failed to generate entropy: {}", e)))?;
        Self::from_entropy(&entropy)
    }

    /// Creates a mnemonic from the given entropy bytes.
    ///
    /// The entropy must be 16, 20, 24, 28, or 32 bytes (128, 160, 192, 224, or 256 bits).
    ///
    /// # Arguments
    ///
    /// * `entropy` - The entropy bytes
    ///
    /// # Returns
    ///
    /// A new `Mnemonic` instance derived from the entropy.
    ///
    /// # Errors
    ///
    /// Returns an error if the entropy length is invalid.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::compat::bip39::Mnemonic;
    ///
    /// let entropy = [0u8; 16]; // 128 bits = 12 words
    /// let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
    /// assert_eq!(mnemonic.phrase(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    /// ```
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        Self::from_entropy_with_language(entropy, Language::English)
    }

    /// Creates a mnemonic from entropy with a specific language.
    pub fn from_entropy_with_language(entropy: &[u8], language: Language) -> Result<Self> {
        // Validate entropy length
        let entropy_bits = entropy.len() * 8;
        #[allow(unknown_lints, clippy::manual_is_multiple_of)]
        if !(128..=256).contains(&entropy_bits) || entropy_bits % 32 != 0 {
            return Err(Error::InvalidEntropyLength {
                expected: "128, 160, 192, 224, or 256 bits".to_string(),
                actual: entropy_bits,
            });
        }

        // Calculate checksum
        let hash = sha256(entropy);
        let checksum_bits = entropy_bits / 32;

        // Convert entropy + checksum to words
        // We need to work with bits, combining entropy and checksum bits
        let total_bits = entropy_bits + checksum_bits;
        let word_count = total_bits / 11;

        let wordlist = language.wordlist();
        let mut words = Vec::with_capacity(word_count);

        // Build a bit stream from entropy + checksum
        // Each word is 11 bits, mapping to an index 0-2047
        for i in 0..word_count {
            let bit_offset = i * 11;
            let mut index: u16 = 0;

            for bit in 0..11 {
                let pos = bit_offset + bit;
                let byte_idx = pos / 8;
                let bit_idx = 7 - (pos % 8);

                let byte = if byte_idx < entropy.len() {
                    entropy[byte_idx]
                } else {
                    // This is in the checksum portion
                    hash[byte_idx - entropy.len()]
                };

                if (byte >> bit_idx) & 1 == 1 {
                    index |= 1 << (10 - bit);
                }
            }

            words.push(wordlist[index as usize].to_string());
        }

        Ok(Self { words, language })
    }

    /// Parses a mnemonic phrase string.
    ///
    /// The phrase is validated for correct word count, valid words, and correct checksum.
    ///
    /// # Arguments
    ///
    /// * `phrase` - The mnemonic phrase as a space-separated string
    ///
    /// # Returns
    ///
    /// A validated `Mnemonic` instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the phrase is invalid.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::compat::bip39::Mnemonic;
    ///
    /// let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
    /// assert!(mnemonic.is_valid());
    /// ```
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        Self::from_phrase_with_language(phrase, Language::English)
    }

    /// Parses a mnemonic phrase with a specific language.
    pub fn from_phrase_with_language(phrase: &str, language: Language) -> Result<Self> {
        // Split into words, handling multiple spaces
        let words: Vec<String> = phrase
            .split_whitespace()
            .map(|s| s.to_lowercase())
            .collect();

        // Validate word count
        let word_count = words.len();
        if word_count != 12
            && word_count != 15
            && word_count != 18
            && word_count != 21
            && word_count != 24
        {
            return Err(Error::InvalidMnemonic(format!(
                "invalid word count: {}, expected 12, 15, 18, 21, or 24",
                word_count
            )));
        }

        // Validate each word exists in wordlist and get indices
        let mut indices = Vec::with_capacity(word_count);
        for word in &words {
            match language.word_index(word) {
                Some(idx) => indices.push(idx),
                None => return Err(Error::InvalidMnemonicWord(word.clone())),
            }
        }

        let mnemonic = Self { words, language };

        // Validate checksum
        if !mnemonic.validate_checksum(&indices)? {
            return Err(Error::InvalidMnemonic("invalid checksum".to_string()));
        }

        Ok(mnemonic)
    }

    /// Validates the checksum of the mnemonic.
    fn validate_checksum(&self, indices: &[usize]) -> Result<bool> {
        let word_count = self.words.len();
        let total_bits = word_count * 11;
        let checksum_bits = word_count / 3; // CS = ENT / 32, and word_count = (ENT + CS) / 11
        let entropy_bits = total_bits - checksum_bits;
        let entropy_bytes = entropy_bits / 8;

        // Extract entropy and checksum from word indices
        let mut bits = vec![false; total_bits];
        for (i, &index) in indices.iter().enumerate() {
            for bit in 0..11 {
                bits[i * 11 + bit] = (index >> (10 - bit)) & 1 == 1;
            }
        }

        // Convert entropy bits to bytes
        let mut entropy = vec![0u8; entropy_bytes];
        for (i, byte) in entropy.iter_mut().enumerate() {
            for bit in 0..8 {
                if bits[i * 8 + bit] {
                    *byte |= 1 << (7 - bit);
                }
            }
        }

        // Compute expected checksum
        let hash = sha256(&entropy);
        let mut expected_checksum_bits = vec![false; checksum_bits];
        for (i, bit) in expected_checksum_bits.iter_mut().enumerate() {
            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);
            *bit = (hash[byte_idx] >> bit_idx) & 1 == 1;
        }

        // Compare with actual checksum bits
        let actual_checksum_bits = &bits[entropy_bits..];
        Ok(actual_checksum_bits == expected_checksum_bits)
    }

    /// Returns the mnemonic phrase as a string.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::compat::bip39::Mnemonic;
    ///
    /// let entropy = [0u8; 16];
    /// let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
    /// println!("{}", mnemonic.phrase());
    /// ```
    pub fn phrase(&self) -> String {
        self.words.join(self.language.separator())
    }

    /// Returns the individual words of the mnemonic.
    pub fn words(&self) -> &[String] {
        &self.words
    }

    /// Returns the language of the mnemonic.
    pub fn language(&self) -> Language {
        self.language
    }

    /// Converts the mnemonic to a 512-bit (64-byte) seed.
    ///
    /// The seed is derived using PBKDF2-HMAC-SHA512 with 2048 iterations.
    /// The salt is "mnemonic" concatenated with the optional passphrase.
    ///
    /// # Arguments
    ///
    /// * `passphrase` - An optional passphrase for additional security
    ///
    /// # Returns
    ///
    /// A 64-byte seed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::compat::bip39::Mnemonic;
    ///
    /// let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
    /// let seed = mnemonic.to_seed("TREZOR");
    /// assert_eq!(seed.len(), 64);
    /// ```
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        // Normalize the mnemonic phrase using NFKD normalization
        let mnemonic_normalized = self.phrase().nfkd_normalize();
        let passphrase_normalized = passphrase.nfkd_normalize();

        // Salt is "mnemonic" + passphrase
        let salt = format!("mnemonic{}", passphrase_normalized);

        // PBKDF2-HMAC-SHA512 with 2048 iterations
        let seed_vec = pbkdf2_sha512(mnemonic_normalized.as_bytes(), salt.as_bytes(), 2048, 64);

        let mut seed = [0u8; 64];
        seed.copy_from_slice(&seed_vec);
        seed
    }

    /// Converts the mnemonic to a seed with an empty passphrase.
    ///
    /// Equivalent to `to_seed("")`.
    pub fn to_seed_normalized(&self) -> [u8; 64] {
        self.to_seed("")
    }

    /// Returns the entropy bytes that were used to generate this mnemonic.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::compat::bip39::Mnemonic;
    ///
    /// let original_entropy = [0u8; 16];
    /// let mnemonic = Mnemonic::from_entropy(&original_entropy).unwrap();
    /// let extracted = mnemonic.entropy();
    /// assert_eq!(extracted, original_entropy);
    /// ```
    pub fn entropy(&self) -> Vec<u8> {
        self.extract_entropy_internal().0
    }

    /// Returns the entropy bytes with checksum appended.
    ///
    /// This is equivalent to Go SDK's `MnemonicToByteArray` function.
    /// The returned bytes contain the original entropy followed by the
    /// checksum bits (padded to a full byte if necessary).
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::compat::bip39::Mnemonic;
    ///
    /// let entropy = [0u8; 16]; // 128 bits
    /// let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
    /// let with_checksum = mnemonic.entropy_with_checksum();
    /// // 128 bits entropy + 4 bits checksum = 132 bits = 17 bytes
    /// assert_eq!(with_checksum.len(), 17);
    /// ```
    pub fn entropy_with_checksum(&self) -> Vec<u8> {
        // Get word indices to extract the full bit stream
        let indices: Vec<usize> = self
            .words
            .iter()
            .map(|w| self.language.word_index(w).unwrap_or(0))
            .collect();

        let word_count = self.words.len();
        let total_bits = word_count * 11;
        let checksum_bit_count = word_count / 3;
        let entropy_bits = total_bits - checksum_bit_count;

        // Calculate full byte size needed
        let full_byte_size = (entropy_bits + checksum_bit_count).div_ceil(8);

        // Extract all bits from word indices
        let mut bits = vec![false; total_bits];
        for (i, &index) in indices.iter().enumerate() {
            for bit in 0..11 {
                bits[i * 11 + bit] = (index >> (10 - bit)) & 1 == 1;
            }
        }

        // Convert to bytes
        let mut result = vec![0u8; full_byte_size];
        for (i, bit) in bits.iter().enumerate() {
            if *bit {
                result[i / 8] |= 1 << (7 - (i % 8));
            }
        }

        result
    }

    /// Internal method to extract entropy from words.
    /// Returns (entropy_bytes, checksum_bit_count).
    fn extract_entropy_internal(&self) -> (Vec<u8>, usize) {
        let word_count = self.words.len();
        let total_bits = word_count * 11;
        let checksum_bits = word_count / 3;
        let entropy_bits = total_bits - checksum_bits;
        let entropy_bytes = entropy_bits / 8;

        // Get word indices
        let indices: Vec<usize> = self
            .words
            .iter()
            .map(|w| self.language.word_index(w).unwrap_or(0))
            .collect();

        // Extract bits from word indices
        let mut bits = vec![false; total_bits];
        for (i, &index) in indices.iter().enumerate() {
            for bit in 0..11 {
                bits[i * 11 + bit] = (index >> (10 - bit)) & 1 == 1;
            }
        }

        // Convert to bytes (excluding checksum)
        let mut entropy = vec![0u8; entropy_bytes];
        for (i, byte) in entropy.iter_mut().enumerate() {
            for bit in 0..8 {
                if bits[i * 8 + bit] {
                    *byte |= 1 << (7 - bit);
                }
            }
        }

        (entropy, checksum_bits)
    }

    /// Validates the mnemonic checksum.
    ///
    /// Returns `true` if the mnemonic has a valid checksum.
    pub fn is_valid(&self) -> bool {
        let indices: Vec<usize> = self
            .words
            .iter()
            .filter_map(|w| self.language.word_index(w))
            .collect();

        if indices.len() != self.words.len() {
            return false;
        }

        self.validate_checksum(&indices).unwrap_or(false)
    }
}

impl std::fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.phrase())
    }
}

/// Extension trait for NFKD normalization of strings.
///
/// BIP-39 requires NFKD normalization for both the mnemonic and passphrase.
/// This implementation passes through strings unchanged, matching the Go SDK behavior.
///
/// ## Compatibility Notes
///
/// - **Go SDK**: Does NOT perform NFKD normalization (passes raw UTF-8 bytes)
/// - **TypeScript SDK**: DOES perform NFKD normalization via `String.normalize('NFKD')`
/// - **This implementation**: Matches Go SDK (no normalization)
///
/// For ASCII passphrases (recommended), all SDKs produce identical seeds.
/// For non-ASCII passphrases, this implementation matches Go SDK but may
/// differ from TypeScript SDK.
///
/// ## Recommendation
///
/// For maximum cross-SDK compatibility, use only ASCII characters in passphrases.
trait NfkdNormalize {
    fn nfkd_normalize(&self) -> String;
}

impl NfkdNormalize for str {
    fn nfkd_normalize(&self) -> String {
        // Pass through unchanged to match Go SDK behavior.
        // The BIP-39 English wordlist contains only ASCII characters, so the
        // mnemonic phrase itself doesn't need normalization.
        //
        // For full NFKD Unicode normalization, add the `unicode-normalization` crate:
        // ```
        // use unicode_normalization::UnicodeNormalization;
        // self.nfkd().collect()
        // ```
        self.to_string()
    }
}

impl NfkdNormalize for String {
    fn nfkd_normalize(&self) -> String {
        self.as_str().nfkd_normalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_word_count_entropy_bytes() {
        assert_eq!(WordCount::Words12.entropy_bytes(), 16);
        assert_eq!(WordCount::Words15.entropy_bytes(), 20);
        assert_eq!(WordCount::Words18.entropy_bytes(), 24);
        assert_eq!(WordCount::Words21.entropy_bytes(), 28);
        assert_eq!(WordCount::Words24.entropy_bytes(), 32);
    }

    #[test]
    fn test_word_count_word_count() {
        assert_eq!(WordCount::Words12.word_count(), 12);
        assert_eq!(WordCount::Words15.word_count(), 15);
        assert_eq!(WordCount::Words18.word_count(), 18);
        assert_eq!(WordCount::Words21.word_count(), 21);
        assert_eq!(WordCount::Words24.word_count(), 24);
    }

    #[test]
    fn test_from_entropy_all_zeros_12_words() {
        let entropy = [0u8; 16];
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(
            mnemonic.phrase(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
    }

    #[test]
    fn test_from_entropy_all_ones_12_words() {
        let entropy = [0xffu8; 16];
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(
            mnemonic.phrase(),
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        );
    }

    #[test]
    fn test_from_phrase_valid() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        assert!(mnemonic.is_valid());
        assert_eq!(mnemonic.words().len(), 12);
    }

    #[test]
    fn test_from_phrase_invalid_word() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword";
        let result = Mnemonic::from_phrase(phrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_phrase_invalid_checksum() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let result = Mnemonic::from_phrase(phrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_entropy_roundtrip() {
        let original = hex::decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f").unwrap();
        let mnemonic = Mnemonic::from_entropy(&original).unwrap();
        let extracted = mnemonic.entropy();
        assert_eq!(original, extracted);
    }

    #[test]
    fn test_to_seed_trezor() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        let seed = mnemonic.to_seed("TREZOR");
        assert_eq!(
            hex::encode(seed),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn test_new_generates_valid_mnemonic() {
        let mnemonic = Mnemonic::new(WordCount::Words12).unwrap();
        assert!(mnemonic.is_valid());
        assert_eq!(mnemonic.words().len(), 12);

        let mnemonic = Mnemonic::new(WordCount::Words24).unwrap();
        assert!(mnemonic.is_valid());
        assert_eq!(mnemonic.words().len(), 24);
    }

    #[test]
    fn test_invalid_entropy_length() {
        let result = Mnemonic::from_entropy(&[0u8; 15]); // 120 bits - invalid
        assert!(result.is_err());

        let result = Mnemonic::from_entropy(&[0u8; 33]); // 264 bits - invalid
        assert!(result.is_err());
    }
}
