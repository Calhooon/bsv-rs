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
//! ## Wordlist Data
//!
//! Each list is a text file beside this module, `<language>.txt`: one word per
//! line, 2048 lines, LF, UTF-8. The files are the `bitcoin/bips` `bip-0039`
//! lists; French, Japanese, Korean and Spanish are stored in NFC (upstream
//! stores them in NFD), the form these arrays have always carried.
//!
//! ## Wordlist Integrity
//!
//! The wordlist integrity is verified by:
//! 1. Compile-time: each `static` is built by the `const fn` `parse` from its
//!    file, so a file with another line count, an empty line, a CR or no final
//!    LF fails the build; the type `[&str; 2048]` is unchanged
//! 2. Runtime: `verify_english_wordlist()` checks the words at index 0 and 2047 against the BIP-39 list

/// Splits a wordlist file into its 2048 words, one per LF-terminated line.
///
/// Evaluated in each `static`'s initializer, so every `panic!` here is a
/// compile error on the data, never a runtime one.
#[allow(clippy::panic)] // #89: called only in the statics' initializers below, so each panic is a compile error on a data file
const fn parse(text: &'static str) -> [&'static str; 2048] {
    let mut words = [""; 2048];
    let mut rest = text.as_bytes();
    let mut i = 0;
    while i < 2048 {
        let mut end = 0;
        while end < rest.len() && rest[end] != b'\n' {
            assert!(rest[end] != b'\r', "a wordlist line carries a CR");
            end += 1;
        }
        assert!(
            end < rest.len(),
            "a wordlist has fewer than 2048 LF-terminated lines"
        );
        assert!(end != 0, "a wordlist line is empty");
        let (word, tail) = rest.split_at(end);
        words[i] = match core::str::from_utf8(word) {
            Ok(word) => word,
            Err(_) => panic!("a wordlist line is not UTF-8"),
        };
        rest = tail.split_at(1).1;
        i += 1;
    }
    assert!(rest.is_empty(), "a wordlist has more than 2048 lines");
    words
}

/// The BIP-39 Chinese Simplified wordlist (2048 words), from `chinese_simplified.txt`.
pub static CHINESE_SIMPLIFIED: [&str; 2048] = parse(include_str!("chinese_simplified.txt"));

/// The BIP-39 Chinese Traditional wordlist (2048 words), from `chinese_traditional.txt`.
pub static CHINESE_TRADITIONAL: [&str; 2048] = parse(include_str!("chinese_traditional.txt"));

/// The BIP-39 Czech wordlist (2048 words), from `czech.txt`.
pub static CZECH: [&str; 2048] = parse(include_str!("czech.txt"));

/// The BIP-39 English wordlist (2048 words), from `english.txt`.
pub static ENGLISH: [&str; 2048] = parse(include_str!("english.txt"));

/// The BIP-39 French wordlist (2048 words), from `french.txt`.
pub static FRENCH: [&str; 2048] = parse(include_str!("french.txt"));

/// The BIP-39 Italian wordlist (2048 words), from `italian.txt`.
pub static ITALIAN: [&str; 2048] = parse(include_str!("italian.txt"));

/// The BIP-39 Japanese wordlist (2048 words), from `japanese.txt`.
pub static JAPANESE: [&str; 2048] = parse(include_str!("japanese.txt"));

/// The BIP-39 Korean wordlist (2048 words), from `korean.txt`.
pub static KOREAN: [&str; 2048] = parse(include_str!("korean.txt"));

/// The BIP-39 Spanish wordlist (2048 words), from `spanish.txt`.
pub static SPANISH: [&str; 2048] = parse(include_str!("spanish.txt"));

/// Verifies the English wordlist integrity.
///
/// Returns `true` if the wordlist matches the BIP-39 specification.
/// This checks:
/// - First word is "abandon"
/// - Last word is "zoo"
/// - Array contains exactly 2048 words (enforced by type system)
#[inline]
#[must_use]
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
