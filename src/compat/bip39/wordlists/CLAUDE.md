# BIP-39 Wordlists
> Static wordlist data for BIP-39 mnemonic phrase generation in 9 languages

## Overview

This module provides the official BIP-39 wordlists used for encoding entropy as human-readable mnemonic phrases. Each wordlist contains exactly 2048 words, allowing 11 bits of entropy to be encoded per word. Nine languages are supported: Chinese Simplified, Chinese Traditional, Czech, English, French, Italian, Japanese, Korean, and Spanish.

## Files

| File | Lines | Purpose |
|------|-------|---------|
| `mod.rs` | 121 | Module declarations, re-exports, `verify_english_wordlist()`, and tests |
| `english.rs` | 224 | Official BIP-39 English wordlist (2048 words, ~9 words/line) |
| `chinese_simplified.rs` | 141 | Official BIP-39 Chinese Simplified wordlist (2048 words, 16 chars/line) |
| `chinese_traditional.rs` | 141 | Official BIP-39 Chinese Traditional wordlist (2048 words, 16 chars/line) |
| `czech.rs` | 244 | Official BIP-39 Czech wordlist (2048 words, ~9 words/line) |
| `french.rs` | 2061 | Official BIP-39 French wordlist (2048 words, 1 word/line) |
| `italian.rs` | 2061 | Official BIP-39 Italian wordlist (2048 words, 1 word/line) |
| `japanese.rs` | 2061 | Official BIP-39 Japanese wordlist (2048 words, 1 word/line) |
| `korean.rs` | 2061 | Official BIP-39 Korean wordlist (2048 words, 1 word/line) |
| `spanish.rs` | 2061 | Official BIP-39 Spanish wordlist (2048 words, 1 word/line) |

## Key Exports

### Wordlist Constants

Each language file exports a single `pub static` array of 2048 words:

```rust
pub static ENGLISH: [&str; 2048]
pub static CHINESE_SIMPLIFIED: [&str; 2048]
pub static CHINESE_TRADITIONAL: [&str; 2048]
pub static CZECH: [&str; 2048]
pub static FRENCH: [&str; 2048]
pub static ITALIAN: [&str; 2048]
pub static JAPANESE: [&str; 2048]
pub static KOREAN: [&str; 2048]
pub static SPANISH: [&str; 2048]
```

All nine are re-exported from `mod.rs`.

### Boundary Words

Each wordlist's first and last words (verified by tests):

| Wordlist | First Word | Last Word |
|----------|-----------|-----------|
| `ENGLISH` | abandon | zoo |
| `CHINESE_SIMPLIFIED` | 的 | 歇 |
| `CHINESE_TRADITIONAL` | 的 | 歇 |
| `CZECH` | abdikace | zvyk |
| `FRENCH` | abaisser | zoologie |
| `ITALIAN` | abaco | zuppa |
| `JAPANESE` | あいこくしん | われる |
| `KOREAN` | 가격 | 힘껏 |
| `SPANISH` | ábaco | zurdo |

### `verify_english_wordlist()`

```rust
#[inline]
pub fn verify_english_wordlist() -> bool
```

Runtime verification function that checks the English wordlist matches the BIP-39 specification. Returns `true` if:
- Array contains exactly 2048 words (also enforced at compile-time by the type)
- First word is "abandon"
- Last word is "zoo"

## Wordlist Integrity

The wordlist integrity is verified at two levels:

1. **Compile-time**: The array type `[&str; 2048]` enforces exactly 2048 words per language
2. **Runtime**: `verify_english_wordlist()` checks English boundary words; tests verify all 9 languages

## Wordlist Properties

BIP-39 wordlists have specific properties for mnemonic generation:

- **Alphabetical sorting**: Words are sorted (enabling efficient lookup)
- **Unique prefixes**: Each word is uniquely identifiable by its first 4 characters (Latin-script languages)
- **Common words**: Words are chosen to be easy to spell and recognize
- **No similar words**: Avoids confusing word pairs (e.g., "build" vs "built")

Wordlist files use different line formatting depending on the language:
- **English, Czech**: ~9 comma-separated words per line (compact, 224/244 lines)
- **Chinese Simplified, Chinese Traditional**: 16 characters per line (141 lines each)
- **French, Italian, Japanese, Korean, Spanish**: 1 word per line (2061 lines each)

## Language Integration

The wordlists are consumed by the `Language` enum in `mnemonic.rs`:

```rust
pub enum Language {
    ChineseSimplified,
    ChineseTraditional,
    Czech,
    #[default]
    English,
    French,
    Italian,
    Japanese,
    Korean,
    Spanish,
}
```

`Language::wordlist()` returns the corresponding `&'static [&'static str; 2048]`.

Japanese uses ideographic space (U+3000) as the word separator per BIP-39 spec; all other languages use ASCII space.

## Usage

The wordlist is typically accessed indirectly through the `Mnemonic` struct:

```rust
use bsv_sdk::compat::bip39::{Mnemonic, Language, WordCount};

// Default language (English)
let mnemonic = Mnemonic::new(WordCount::Words12)?;

// Specific language
let entropy = [0u8; 16];
let mnemonic = Mnemonic::from_entropy_with_language(&entropy, Language::Japanese)?;

// Parse a phrase in a specific language
let mnemonic = Mnemonic::from_phrase_with_language(phrase, Language::French)?;
```

Direct access to wordlists:

```rust
use bsv_sdk::compat::bip39::wordlists::{ENGLISH, JAPANESE, SPANISH};

// Look up word at specific index
let word = ENGLISH[0];      // "abandon"
let word = JAPANESE[0];     // "あいこくしん"
let word = SPANISH[2047];   // "zurdo"

// Find index of a word
let index = ENGLISH.iter().position(|&w| w == "abandon");
assert_eq!(index, Some(0));
```

## Index to Word Mapping

The array index maps directly to the 11-bit value during mnemonic encoding:

| Index | English | 11-bit Value |
|-------|---------|--------------|
| 0 | abandon | 00000000000 |
| 1 | ability | 00000000001 |
| 2 | able | 00000000010 |
| ... | ... | ... |
| 2046 | zone | 11111111110 |
| 2047 | zoo | 11111111111 |

## File Format

Each wordlist file follows the same pattern:

```rust
//! {Language} BIP-39 wordlist.
//! Source: <https://github.com/bitcoin/bips/blob/master/bip-0039/{language}.txt>

/// The BIP-39 {Language} wordlist (2048 words).
pub static {LANGUAGE}: [&str; 2048] = [
    "word1", "word2", ...
];
```

English and Czech format ~9 words per line. Chinese formats 16 characters per line. French, Italian, Japanese, Korean, and Spanish format 1 word per line.

## Tests

The module includes 4 tests in `mod.rs`:

| Test | Purpose |
|------|---------|
| `test_english_wordlist_integrity` | Verifies English word count (2048) and boundary words at indices 0, 1, 2046, 2047 |
| `test_wordlist_is_sorted_first_chars` | Confirms English alphabetical ordering (`ENGLISH[0]` < `ENGLISH[2047]`) |
| `test_all_wordlists_have_2048_words` | Asserts all 9 wordlists contain exactly 2048 words |
| `test_wordlist_first_last_words` | Verifies first and last words for all 8 non-English wordlists match BIP-39 spec |

## Adding New Languages

To add support for an additional BIP-39 language:

1. Create `{language}.rs` with `pub static {LANGUAGE}: [&str; 2048] = [...]`
2. Add `mod {language};` and `pub use {language}::{LANGUAGE};` in `mod.rs`
3. Add boundary word checks to `test_wordlist_first_last_words` and a length check to `test_all_wordlists_have_2048_words`
4. Add a variant to the `Language` enum in `mnemonic.rs`
5. Update `Language::wordlist()` and `Language::separator()` in `mnemonic.rs`

## Related Documentation

- `../CLAUDE.md` - Parent BIP-39 module documentation
- `../../CLAUDE.md` - Compat module overview
- `../mnemonic.rs` - `Mnemonic` struct and `Language` enum that consume wordlists
