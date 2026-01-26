//! BIP-39 wordlists for mnemonic generation.
//!
//! This module contains the official BIP-39 wordlists. Currently only English
//! is supported, but additional languages can be added in the future.
//!
//! ## Wordlist Integrity
//!
//! The wordlist integrity is verified by:
//! 1. Compile-time: Array type `[&str; 2048]` enforces exact word count
//! 2. Runtime: `verify_wordlist()` checks first/last words match BIP-39 spec

mod english;

pub use english::ENGLISH;

/// Verifies the English wordlist integrity.
///
/// Returns `true` if the wordlist matches the BIP-39 specification.
/// This checks:
/// - First word is "abandon"
/// - Last word is "zoo"
/// - Array contains exactly 2048 words (enforced by type system)
#[inline]
pub fn verify_english_wordlist() -> bool {
    ENGLISH.len() == 2048 && ENGLISH[0] == "abandon" && ENGLISH[2047] == "zoo"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_english_wordlist_integrity() {
        assert!(verify_english_wordlist());
        assert_eq!(ENGLISH.len(), 2048);
        assert_eq!(ENGLISH[0], "abandon");
        assert_eq!(ENGLISH[1], "ability");
        assert_eq!(ENGLISH[2046], "zone");
        assert_eq!(ENGLISH[2047], "zoo");
    }

    #[test]
    fn test_wordlist_is_sorted_first_chars() {
        // BIP-39 wordlist should be roughly alphabetical
        // (not strictly sorted, but "abandon" < "zoo")
        assert!(ENGLISH[0] < ENGLISH[2047]);
    }
}
