# BIP-39 Wordlists
> Static wordlist data for BIP-39 mnemonic phrase generation

## Overview

This module provides the official BIP-39 wordlists used for encoding entropy as human-readable mnemonic phrases. Each wordlist contains exactly 2048 words, allowing 11 bits of entropy to be encoded per word. Currently only the English wordlist is implemented.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module declaration, re-exports, and verification function |
| `english.rs` | Official BIP-39 English wordlist (2048 words) |

## Key Exports

### `ENGLISH`

```rust
pub static ENGLISH: [&str; 2048]
```

A static array containing the 2048 words from the official BIP-39 English wordlist. Words are sorted alphabetically and indexed from 0-2047, where each index corresponds to an 11-bit value in the mnemonic encoding.

**Source**: [BIP-39 English wordlist](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt)

### `verify_english_wordlist()`

```rust
pub fn verify_english_wordlist() -> bool
```

Runtime verification function that checks the English wordlist matches the BIP-39 specification. Returns `true` if:
- Array contains exactly 2048 words (also enforced at compile-time by the type)
- First word is "abandon"
- Last word is "zoo"

## Wordlist Integrity

The wordlist integrity is verified at two levels:

1. **Compile-time**: The array type `[&str; 2048]` enforces exactly 2048 words
2. **Runtime**: `verify_english_wordlist()` checks boundary words match BIP-39 spec

## Wordlist Properties

The BIP-39 English wordlist has specific properties that make it suitable for mnemonic generation:

- **Alphabetical sorting**: Words are sorted alphabetically, enabling binary search
- **Unique prefixes**: Each word is uniquely identifiable by its first 4 characters
- **Common words**: Words are chosen to be easy to spell and recognize
- **No similar words**: Avoids confusing word pairs (e.g., "build" vs "built")

## Usage

The wordlist is typically accessed indirectly through the `Mnemonic` struct:

```rust
use bsv_sdk::compat::bip39::{Mnemonic, WordCount};

// Generate creates words from ENGLISH wordlist
let mnemonic = Mnemonic::new(WordCount::Words12)?;

// Each word is from the ENGLISH array
for word in mnemonic.words() {
    // word is guaranteed to be in wordlists::ENGLISH
}
```

Direct access to the wordlist:

```rust
use bsv_sdk::compat::bip39::wordlists::ENGLISH;

// Look up word at specific index
let word = ENGLISH[0];      // "abandon"
let word = ENGLISH[2047];   // "zoo"

// Find index of a word
let index = ENGLISH.iter().position(|&w| w == "abandon");
assert_eq!(index, Some(0));
```

Verify wordlist integrity:

```rust
use bsv_sdk::compat::bip39::wordlists::verify_english_wordlist;

assert!(verify_english_wordlist());
```

## Index to Word Mapping

The array index maps directly to the 11-bit value during mnemonic encoding:

| Index | Word | 11-bit Value |
|-------|------|--------------|
| 0 | abandon | 00000000000 |
| 1 | ability | 00000000001 |
| 2 | able | 00000000010 |
| ... | ... | ... |
| 2046 | zone | 11111111110 |
| 2047 | zoo | 11111111111 |

## Sample Words

First 10 words (indices 0-9):
- abandon, ability, able, about, above, absent, absorb, abstract, absurd, abuse

Last 10 words (indices 2038-2047):
- yard, year, yellow, you, young, youth, zebra, zero, zone, zoo

## Tests

The module includes tests in `mod.rs`:

- `test_english_wordlist_integrity`: Verifies correct word count and boundary words (checks indices 0, 1, 2046, 2047)
- `test_wordlist_is_sorted_first_chars`: Confirms alphabetical ordering by comparing first and last words

## Adding New Languages

To add support for additional languages (e.g., Spanish, Japanese):

1. Create a new file `{language}.rs` with the 2048 words
2. Export the wordlist as `pub static {LANGUAGE}: [&str; 2048]`
3. Update `mod.rs` to declare and re-export the new module
4. Add a corresponding `verify_{language}_wordlist()` function
5. Update `Language` enum in `mnemonic.rs` to include the new language

## Related Documentation

- `../CLAUDE.md` - Parent BIP-39 module documentation
- `../../CLAUDE.md` - Compat module overview
- `../mnemonic.rs` - Mnemonic struct that uses wordlists
