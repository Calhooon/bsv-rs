# BIP-39 Wordlists
> The nine BIP-39 wordlists as text files, parsed into `pub static` arrays at compile time

## Overview

The official BIP-39 wordlists for encoding entropy as mnemonic phrases, 2048 words each (11 bits per word), in nine languages: Chinese Simplified, Chinese Traditional, Czech, English, French, Italian, Japanese, Korean and Spanish. Since #89 the words are data, not code: each language is a text file, and `mod.rs` turns each file into its array in the `static`'s initializer.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | `const fn parse`, the nine `pub static` arrays (`include_str!` of each file), `verify_english_wordlist()`, 4 unit tests |
| `<language>.txt` (nine) | One word per line, 2048 lines, LF, UTF-8, a final LF; no other byte |

`.gitattributes` marks `src/compat/bip39/wordlists/*.txt -text`: a CRLF checkout would put a CR in every line, and the parser refuses it at compile time.

## The public items (unchanged by #89)

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
pub fn verify_english_wordlist() -> bool
```

A downstream can name these with their types (`bsv_rs::compat::bip39::wordlists::ENGLISH`), so the shape is a semver contract: name, `static`, `[&str; 2048]`. `parse` is private.

## How a file becomes an array

`pub static ENGLISH: [&str; 2048] = parse(include_str!("english.txt"));`

`parse` is a `const fn` that walks the bytes, cuts at each `\n`, and checks each word with `core::str::from_utf8` (const since 1.63; `split_at` since 1.71; MSRV 1.88 builds it). It runs in the static's initializer, i.e. in the compiler, so a bad file is a build error (`error[E0080]: evaluation panicked: ...`), never a runtime panic and never a lazy initialization:

| File fault | Build error |
|------------|-------------|
| fewer than 2048 lines, or no final LF | `a wordlist has fewer than 2048 LF-terminated lines` |
| more than 2048 lines | `a wordlist has more than 2048 lines` |
| an empty line | `a wordlist line is empty` |
| a CR anywhere (a CRLF checkout) | `a wordlist line carries a CR` |

No build script, no `OUT_DIR`, no runtime cost: the arrays are in the binary's read-only data exactly as the old `.rs` tables put them. `include_str!` resolves at compile time on every target, wasm32 included. The `.txt` files ship in the crates.io package (nothing in `Cargo.toml`'s `exclude` names them).

## Provenance and normalization

Upstream is `bitcoin/bips` `bip-0039/<language>.txt`, read at `100ba872c808946155b1eeb8c4568058f2eea0a7` (2026-10-24). Five files are byte-identical to upstream: English, Chinese Simplified, Chinese Traditional, Czech, Italian. Upstream stores French, Japanese, Korean and Spanish in Unicode NFD; this crate's arrays have always carried their NFC form, and the files keep it (the words did not change in #89). Since #163 the form does not matter to a reader: the lookup compares both sides in NFKD and `to_seed` hashes the NFKD phrase (before #163 both used the bytes as given); the phrase a `Mnemonic` prints is NFC, the form of the files.

| File | sha256 (the file, 64 hex) | Upstream at `100ba872` |
|------|--------|--------|
| `english.txt` | `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda` | same |
| `chinese_simplified.txt` | `5c5942792bd8340cb8b27cd592f1015edf56a8c5b26276ee18a482428e7c5726` | same |
| `chinese_traditional.txt` | `417b26b3d8500a4ae3d59717d7011952db6fc2fb84b807f3f94ac734e89c1b5f` | same |
| `czech.txt` | `7e80e161c3e93d9554c2efb78d4e3cebf8fc727e9c52e03b83b94406bdcc95fc` | same |
| `italian.txt` | `d392c49fdb700a24cd1fceb237c1f65dcc128f6b34a8aacb58b59384b5c648c2` | same |
| `french.txt` | `431c1d074225d2b7e82db857d7c3ea58051df546e7c8b74c1f6dcab36351fd56` | `ebc3959ab7801a1df6bac4fa7d970652f1df76b683cd2f4003c941c63d517e59` (NFD) |
| `japanese.txt` | `c58cb719f782910cfcedb6ab64dc506322bd7ce4f7cede5a0563ac06d3d5c884` | `2eed0aef492291e061633d7ad8117f1a2b03eb80a29d0e4e3117ac2528d05ffd` (NFD) |
| `korean.txt` | `4e9e6759fceb0235d6c46f0364c1c2ce541521001a9add34049aa47500872ddf` | `9e95f86c167de88f450f0aaf89e87f6624a57f973c67b516e338e8e8b8897f60` (NFD) |
| `spanish.txt` | `0c639b0d58b6e56c18dcf418017ff341418a129e45fbf303361e8569edb02efe` | `46846a5a0139d1e3cb77293e521c2865f7bcdb82c44e8d0a06a2cd0ecba48c0b` (NFD) |

The file digests are pinned in `tests/compat_bip39_wordlist_files.rs`. To check a file against upstream: `shasum -a 256` for the five; for the four, NFC-normalize each upstream line (Python's `unicodedata.normalize('NFC', line)`) and compare bytes.

## Boundary Words

| Wordlist | Word 0 | Word 2047 |
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

## Language Integration

`Language::wordlist()` in `../mnemonic.rs` returns `&'static [&'static str; 2048]` (`&wordlists::ENGLISH`, ...); the index of a word is its 11-bit value (`ENGLISH[0]` "abandon" is `00000000000`, `ENGLISH[2047]` "zoo" is `11111111111`). Japanese joins words with the ideographic space U+3000; every other language with an ASCII space.

## Tests

- `mod.rs` (4 unit tests): English integrity at indices 0, 1, 2046, 2047; English ordering; all nine have 2048 words; every list's words at index 0 and 2047.
- `tests/compat_bip39_wordlist_files.rs` (10): per language, the file's sha256, the file's lines equal to the `static` element for element, and the words at index 0 and 2047; `verify_english_wordlist()`.
- `tests/compat_bip39_tests.rs` (29): the TREZOR vectors and the cross-SDK cases through `Mnemonic`.

Never edit a `.txt` to make a test pass: a changed word is a changed mnemonic for every user of that language.

## Adding a Language

1. Add `<language>.txt` (one word per line, 2048 lines, LF, a final LF), from upstream, in NFC.
2. In `mod.rs`: `pub static <LANGUAGE>: [&str; 2048] = parse(include_str!("<language>.txt"));` with a doc line, and the unit tests' length and boundary checks.
3. A `pin!` line in `tests/compat_bip39_wordlist_files.rs` with the file's sha256.
4. A `Language` variant and its `wordlist()` and `separator()` arms in `../mnemonic.rs`.

## Related Documentation

- `../CLAUDE.md`: the BIP-39 module
- `../../CLAUDE.md`: the compat module
- `docs/RATCHETS.md`: the census reads `.rs` files only; nothing here is exempt
