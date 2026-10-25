#![no_main]
//! The BIP-39 readers (`compat::bip39`) on arbitrary input: the input as a
//! phrase in each of the nine languages (`Mnemonic::from_phrase_with_language`,
//! `from_binary` for English), and as entropy (`from_entropy`). The assertion
//! is that each returns. A phrase is read case- and space-insensitively, so
//! the round trip is the canonical form: a parsed phrase prints a phrase that
//! parses to the same words, and its entropy writes that phrase again; an
//! entropy's phrase parses back to the same entropy bytes.
use bsv_rs::compat::bip39::{Language, Mnemonic};
use libfuzzer_sys::fuzz_target;

const LANGUAGES: [Language; 9] = [
    Language::ChineseSimplified,
    Language::ChineseTraditional,
    Language::Czech,
    Language::English,
    Language::French,
    Language::Italian,
    Language::Japanese,
    Language::Korean,
    Language::Spanish,
];

fn canonical(mnemonic: &Mnemonic, language: Language) {
    assert!(mnemonic.is_valid());
    let phrase = mnemonic.phrase();
    let again = Mnemonic::from_phrase_with_language(&phrase, language).expect("its phrase parses");
    assert_eq!(again.words(), mnemonic.words());
    let entropy = mnemonic.entropy();
    let written = Mnemonic::from_entropy_with_language(&entropy, language).expect("its entropy");
    assert_eq!(written.phrase(), phrase);
}

fuzz_target!(|data: &[u8]| {
    if let Ok(mnemonic) = Mnemonic::from_entropy(data) {
        let again = Mnemonic::from_phrase(&mnemonic.phrase()).expect("its phrase parses");
        assert_eq!(again.entropy(), data);
    }
    if let Ok(mnemonic) = Mnemonic::from_binary(data) {
        canonical(&mnemonic, Language::English);
        let bytes = mnemonic.to_binary();
        let again = Mnemonic::from_binary(&bytes).expect("its bytes parse");
        assert_eq!(again.to_binary(), bytes);
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for language in LANGUAGES {
        if let Ok(mnemonic) = Mnemonic::from_phrase_with_language(text, language) {
            canonical(&mnemonic, language);
        }
    }
});
