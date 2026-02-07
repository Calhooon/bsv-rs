//! BIP-39 wordlists for mnemonic generation.
//!
//! This module contains the official BIP-39 wordlists for multiple languages.
//!
//! ## Supported Languages
//!
//! - English
//! - Chinese Simplified
//! - Chinese Traditional
//! - Czech
//! - French
//! - Italian
//! - Japanese
//! - Korean
//! - Spanish
//!
//! ## Wordlist Integrity
//!
//! The wordlist integrity is verified by:
//! 1. Compile-time: Array type `[&str; 2048]` enforces exact word count
//! 2. Runtime: `verify_wordlist()` checks first/last words match BIP-39 spec

mod chinese_simplified;
mod chinese_traditional;
mod czech;
mod english;
mod french;
mod italian;
mod japanese;
mod korean;
mod spanish;

pub use chinese_simplified::CHINESE_SIMPLIFIED;
pub use chinese_traditional::CHINESE_TRADITIONAL;
pub use czech::CZECH;
pub use english::ENGLISH;
pub use french::FRENCH;
pub use italian::ITALIAN;
pub use japanese::JAPANESE;
pub use korean::KOREAN;
pub use spanish::SPANISH;

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

    #[test]
    fn test_all_wordlists_have_2048_words() {
        assert_eq!(CHINESE_SIMPLIFIED.len(), 2048);
        assert_eq!(CHINESE_TRADITIONAL.len(), 2048);
        assert_eq!(CZECH.len(), 2048);
        assert_eq!(ENGLISH.len(), 2048);
        assert_eq!(FRENCH.len(), 2048);
        assert_eq!(ITALIAN.len(), 2048);
        assert_eq!(JAPANESE.len(), 2048);
        assert_eq!(KOREAN.len(), 2048);
        assert_eq!(SPANISH.len(), 2048);
    }

    #[test]
    fn test_wordlist_first_last_words() {
        // Verify first and last words match BIP-39 specification
        // Chinese Simplified: first=的 last=歇
        assert_eq!(CHINESE_SIMPLIFIED[0], "的");
        assert_eq!(CHINESE_SIMPLIFIED[2047], "歇");

        // Chinese Traditional: first=的 last=歇
        assert_eq!(CHINESE_TRADITIONAL[0], "的");
        assert_eq!(CHINESE_TRADITIONAL[2047], "歇");

        assert_eq!(CZECH[0], "abdikace");
        assert_eq!(CZECH[2047], "zvyk");

        assert_eq!(FRENCH[0], "abaisser");
        assert_eq!(FRENCH[2047], "zoologie");

        assert_eq!(ITALIAN[0], "abaco");
        assert_eq!(ITALIAN[2047], "zuppa");

        // Japanese: first=あいこくしん last=われる
        assert_eq!(JAPANESE[0], "あいこくしん");
        assert_eq!(JAPANESE[2047], "われる");

        // Korean: first=가격 last=힘껏
        assert_eq!(KOREAN[0], "가격");
        assert_eq!(KOREAN[2047], "힘껏");

        // Spanish: first=ábaco last=zurdo
        assert_eq!(SPANISH[0], "ábaco");
        assert_eq!(SPANISH[2047], "zurdo");
    }
}
