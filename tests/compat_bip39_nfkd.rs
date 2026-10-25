//! BIP-39's NFKD rule (#163): a phrase is NFKD-normalized before its words are
//! looked up, the wordlists are compared in the same form, and the seed is
//! PBKDF2 over the NFKD phrase and the NFKD passphrase
//! (`bitcoin/bips@100ba872` `bip-0039.mediawiki:86-87,94-96`).
//!
//! The expected seeds outside the Japanese vectors were computed with Python's
//! `hashlib.pbkdf2_hmac` over `unicodedata.normalize('NFKD', ...)`, independent
//! of this crate. `tests/vectors/bip39_japanese.json` is
//! `bip32JP/bip32JP.github.io@5a43706` `test_JP_BIP39.json` byte for byte
//! (public domain; the file BIP-39 names at `bip-0039.mediawiki:135`).

#![cfg(feature = "compat")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::compat::bip39::{wordlists, Language, Mnemonic};
use bsv_rs::Error;

/// The Latin letters of the French and Spanish lists, decomposed by hand, so
/// the NFD phrases below do not come from the normalizer under test.
fn decompose_latin(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        let (base, mark) = match c {
            'á' => ('a', '\u{301}'),
            'é' => ('e', '\u{301}'),
            'í' => ('i', '\u{301}'),
            'ó' => ('o', '\u{301}'),
            'ú' => ('u', '\u{301}'),
            'à' => ('a', '\u{300}'),
            'è' => ('e', '\u{300}'),
            'ù' => ('u', '\u{300}'),
            'â' => ('a', '\u{302}'),
            'ê' => ('e', '\u{302}'),
            'î' => ('i', '\u{302}'),
            'ô' => ('o', '\u{302}'),
            'û' => ('u', '\u{302}'),
            'ë' => ('e', '\u{308}'),
            'ï' => ('i', '\u{308}'),
            'ü' => ('u', '\u{308}'),
            'ç' => ('c', '\u{327}'),
            'ñ' => ('n', '\u{303}'),
            'Ñ' => ('N', '\u{303}'),
            _ => {
                out.push(c);
                continue;
            }
        };
        out.push(base);
        out.push(mark);
    }
    out
}

/// A Hangul syllable decomposed into its conjoining jamo (Unicode 3.12),
/// by arithmetic rather than by the normalizer under test.
fn decompose_hangul(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        let cp = c as u32;
        if (0xAC00..=0xD7A3).contains(&cp) {
            let index = cp - 0xAC00;
            let l = 0x1100 + index / (21 * 28);
            let v = 0x1161 + (index % (21 * 28)) / 28;
            let t = index % 28;
            out.push(char::from_u32(l).unwrap());
            out.push(char::from_u32(v).unwrap());
            if t != 0 {
                out.push(char::from_u32(0x11A7 + t).unwrap());
            }
        } else {
            out.push(c);
        }
    }
    out
}

const ENTROPY_00_0F: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

const SPANISH_PHRASE: &str =
    "ábaco álbum líquido álbum espuma acudir bolero bosque amante gaita dictar boca";
const SPANISH_SEED: &str = "21d369cf994a9b2d99c938c979d9ca95ceeb7ac55589622bf57e2f53e7edf7688eb32a140ac9206dbf219376a8ffc7ecf4d642a88834a1dfb633d75a34180b60";

const FRENCH_PHRASE: &str =
    "abaisser agréable inductif agréable éligible achat bolide boucle amateur exister dérober bloquer";
const FRENCH_SEED: &str = "b70232fad2698ee7236b5f789e1566157f41e9b0a22b4dfa0c3325172a6fd8513e0d552a12c335737275847d5b25a24bfaad97bdb4d98541901d3bd2a9cbfcf1";

const KOREAN_PHRASE: &str = "가격 걱정 심부름 걱정 별도 갈색 기법 기운 경력 산길 미술 기념";
const KOREAN_SEED: &str = "c84d23b603720bc67db1b1f5f1cbfc82b760736ad8069bf283c8d5d2a5b1e2075e73208fbe8763500b572839ff3c7827917a7d8eec19b2732152f84b0ace5b70";

fn assert_nfd_accepted(language: Language, nfc: &str, seed_hex: &str) {
    let nfd = decompose_latin(&decompose_hangul(nfc));
    assert_ne!(nfd, nfc, "the fixture must carry a decomposable character");

    let from_entropy = Mnemonic::from_entropy_with_language(&ENTROPY_00_0F, language).unwrap();
    assert_eq!(from_entropy.phrase(), nfc, "the printed form is the list's");

    let a = Mnemonic::from_phrase_with_language(nfc, language).unwrap();
    let b = Mnemonic::from_phrase_with_language(&nfd, language).unwrap();
    assert_eq!(a.entropy(), ENTROPY_00_0F);
    assert_eq!(b.entropy(), ENTROPY_00_0F);
    // The phrase a Mnemonic prints is the list's form, whatever form it was read in.
    assert_eq!(b.phrase(), nfc);
    assert_eq!(hex::encode(a.to_seed("")), seed_hex);
    assert_eq!(hex::encode(b.to_seed("")), seed_hex);
}

#[test]
fn an_nfd_spanish_phrase_is_accepted_and_seeds_as_bip39_says() {
    assert_nfd_accepted(Language::Spanish, SPANISH_PHRASE, SPANISH_SEED);
}

#[test]
fn an_nfd_french_phrase_is_accepted_and_seeds_as_bip39_says() {
    assert_nfd_accepted(Language::French, FRENCH_PHRASE, FRENCH_SEED);
}

#[test]
fn an_nfd_korean_phrase_is_accepted_and_seeds_as_bip39_says() {
    assert_nfd_accepted(Language::Korean, KOREAN_PHRASE, KOREAN_SEED);
}

#[derive(serde::Deserialize)]
struct JapaneseVector {
    entropy: String,
    mnemonic: String,
    passphrase: String,
    seed: String,
}

fn japanese_vectors() -> Vec<JapaneseVector> {
    serde_json::from_str(include_str!("vectors/bip39_japanese.json")).unwrap()
}

#[test]
fn every_japanese_vector_reads_and_seeds_with_its_nfkd_passphrase() {
    let vectors = japanese_vectors();
    assert_eq!(vectors.len(), 24);
    for v in &vectors {
        let entropy = hex::decode(&v.entropy).unwrap();
        let written = Mnemonic::from_entropy_with_language(&entropy, Language::Japanese).unwrap();
        assert_eq!(written.phrase(), v.mnemonic, "entropy {}", v.entropy);

        let read = Mnemonic::from_phrase_with_language(&v.mnemonic, Language::Japanese).unwrap();
        assert_eq!(read.entropy(), entropy, "entropy {}", v.entropy);
        assert_eq!(
            hex::encode(read.to_seed(&v.passphrase)),
            v.seed,
            "entropy {}",
            v.entropy
        );
    }
}

#[test]
fn a_japanese_phrase_reads_the_same_with_ideographic_or_ascii_spaces() {
    for v in &japanese_vectors() {
        let ascii = v.mnemonic.replace('\u{3000}', " ");
        assert_ne!(ascii, v.mnemonic);
        let m = Mnemonic::from_phrase_with_language(&ascii, Language::Japanese).unwrap();
        assert_eq!(
            m.phrase(),
            v.mnemonic,
            "printed with U+3000 whatever it was read with"
        );
        assert_eq!(hex::encode(m.to_seed(&v.passphrase)), v.seed);
    }
}

#[test]
fn a_phrase_whose_normalization_adds_a_word_is_refused_by_its_count() {
    // U+00B4 ACUTE ACCENT is not whitespace, and its NFKD form is a space and
    // U+0301: twelve tokens as typed, thirteen once normalized.
    let phrase = format!("{SPANISH_PHRASE}\u{b4}");
    assert_eq!(phrase.split_whitespace().count(), 12);
    let err = Mnemonic::from_phrase_with_language(&phrase, Language::Spanish).unwrap_err();
    assert_eq!(
        err,
        Error::InvalidMnemonic(
            "invalid word count: 13, expected 12, 15, 18, 21, or 24".to_string()
        )
    );
}

#[test]
fn an_nfd_passphrase_seeds_as_the_nfc_passphrase() {
    let m = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .unwrap();
    let nfc = "Ñandú";
    let nfd = decompose_latin(nfc);
    assert_ne!(nfd, nfc);
    let expected = "f20eed5d4f69027fa057fb07e9f3741e999ac4428597b24c5b3ee7c09b6d6cc6c0babcb162c45a86f91003c91a3d5a51566d70ef6dadf97b1bc34acbfe8f1560";
    assert_eq!(hex::encode(m.to_seed(nfc)), expected);
    assert_eq!(hex::encode(m.to_seed(&nfd)), expected);
}

#[test]
fn every_list_word_is_its_own_nfkc_form() {
    // `word_index` compares a word's NFKC form with the list's bytes, which is
    // BIP-39's NFKD comparison only while every list word is its own NFKC form
    // (two strings share an NFKD form exactly when they share an NFKC form).
    let lists: [(Language, &[&str; 2048]); 9] = [
        (Language::ChineseSimplified, &wordlists::CHINESE_SIMPLIFIED),
        (
            Language::ChineseTraditional,
            &wordlists::CHINESE_TRADITIONAL,
        ),
        (Language::Czech, &wordlists::CZECH),
        (Language::English, &wordlists::ENGLISH),
        (Language::French, &wordlists::FRENCH),
        (Language::Italian, &wordlists::ITALIAN),
        (Language::Japanese, &wordlists::JAPANESE),
        (Language::Korean, &wordlists::KOREAN),
        (Language::Spanish, &wordlists::SPANISH),
    ];
    for (language, list) in lists {
        for (i, word) in list.iter().enumerate() {
            let nfkc: String = unicode_normalization::UnicodeNormalization::nfkc(*word).collect();
            assert_eq!(&nfkc, word, "{language:?} word {i}");
        }
    }
}
