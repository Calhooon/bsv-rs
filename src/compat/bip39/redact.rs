//! No secret is printed by `Debug` (the secret Debug lane, 2026-11-10,
//! C-DEBUG): a `{:?}` of a [`Mnemonic`], or of a struct a dependent derives
//! `Debug` on that holds one, in a log line or a panic message, would write
//! the seed. `Display` and [`Mnemonic::phrase`] are the explicit conversions
//! to the phrase and stay; `tests/secret_debug.rs` pins both outputs.

use super::{Language, Mnemonic};
use crate::Error;

/// `Mnemonic(<redacted, 12 words, English>)`: the word count and language,
/// never a word.
impl std::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Mnemonic(<redacted, {} words, {:?}>)",
            self.words().len(),
            self.language()
        )
    }
}

/// The phrase, its words joined by the language's separator: the explicit
/// conversion to the secret, as [`Mnemonic::phrase`] is. A `{}` of a
/// mnemonic in a log line writes the seed's words; `{:?}` is the redacted
/// form for a log.
impl std::fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.phrase())
    }
}

/// The refusal of a word no list holds, by its position (zero-based here,
/// written from one), never the word: a mistyped word of a phrase is most of
/// the word, and an error is logged. The reference echoes the word
/// (`ts-stack@edf6e03` `compat/Mnemonic.ts:332`), the root `CLAUDE.md` row.
pub(super) fn unknown_word(position: usize, count: usize, language: Language) -> Error {
    Error::InvalidMnemonicWord(format!(
        "word {} of {} is not in the {:?} wordlist",
        position + 1,
        count,
        language
    ))
}
