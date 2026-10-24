//! The BIP-39 wordlists are data files, parsed at compile time (#89).
//!
//! Each test pins one `src/compat/bip39/wordlists/<language>.txt` by its
//! sha256, proves the public `static` is exactly that file's lines, and checks
//! the list's first and last words. The five lists stored as upstream stores
//! them carry upstream's digest at `bitcoin/bips@100ba872`; French, Japanese,
//! Korean and Spanish are the NFC form of upstream's NFD files, the words these
//! arrays carried before #89.

#![cfg(feature = "compat")]

use bsv_rs::compat::bip39::verify_english_wordlist;
use bsv_rs::compat::bip39::wordlists::*;
use bsv_rs::primitives::{sha256, to_hex};

fn check(text: &str, sha: &str, list: &[&str; 2048], first: &str, last: &str) {
    assert_eq!(to_hex(&sha256(text.as_bytes())), sha);
    let lines: Vec<&str> = text.split_terminator('\n').collect();
    assert_eq!(lines.len(), 2048);
    assert_eq!(lines.as_slice(), list.as_slice());
    assert_eq!(list[0], first);
    assert_eq!(list[2047], last);
}

macro_rules! pin {
    ($name:ident, $file:literal, $list:ident, $sha:literal, $first:literal, $last:literal) => {
        #[test]
        fn $name() {
            let text = include_str!(concat!("../src/compat/bip39/wordlists/", $file));
            check(text, $sha, &$list, $first, $last);
        }
    };
}

pin!(
    the_english_wordlist_file_is_pinned_and_is_the_array,
    "english.txt",
    ENGLISH,
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
    "abandon",
    "zoo"
);
pin!(
    the_chinese_simplified_wordlist_file_is_pinned_and_is_the_array,
    "chinese_simplified.txt",
    CHINESE_SIMPLIFIED,
    "5c5942792bd8340cb8b27cd592f1015edf56a8c5b26276ee18a482428e7c5726",
    "的",
    "歇"
);
pin!(
    the_chinese_traditional_wordlist_file_is_pinned_and_is_the_array,
    "chinese_traditional.txt",
    CHINESE_TRADITIONAL,
    "417b26b3d8500a4ae3d59717d7011952db6fc2fb84b807f3f94ac734e89c1b5f",
    "的",
    "歇"
);
pin!(
    the_czech_wordlist_file_is_pinned_and_is_the_array,
    "czech.txt",
    CZECH,
    "7e80e161c3e93d9554c2efb78d4e3cebf8fc727e9c52e03b83b94406bdcc95fc",
    "abdikace",
    "zvyk"
);
pin!(
    the_french_wordlist_file_is_pinned_and_is_the_array,
    "french.txt",
    FRENCH,
    "431c1d074225d2b7e82db857d7c3ea58051df546e7c8b74c1f6dcab36351fd56",
    "abaisser",
    "zoologie"
);
pin!(
    the_italian_wordlist_file_is_pinned_and_is_the_array,
    "italian.txt",
    ITALIAN,
    "d392c49fdb700a24cd1fceb237c1f65dcc128f6b34a8aacb58b59384b5c648c2",
    "abaco",
    "zuppa"
);
pin!(
    the_japanese_wordlist_file_is_pinned_and_is_the_array,
    "japanese.txt",
    JAPANESE,
    "c58cb719f782910cfcedb6ab64dc506322bd7ce4f7cede5a0563ac06d3d5c884",
    "あいこくしん",
    "われる"
);
pin!(
    the_korean_wordlist_file_is_pinned_and_is_the_array,
    "korean.txt",
    KOREAN,
    "4e9e6759fceb0235d6c46f0364c1c2ce541521001a9add34049aa47500872ddf",
    "가격",
    "힘껏"
);
pin!(
    the_spanish_wordlist_file_is_pinned_and_is_the_array,
    "spanish.txt",
    SPANISH,
    "0c639b0d58b6e56c18dcf418017ff341418a129e45fbf303361e8569edb02efe",
    "ábaco",
    "zurdo"
);

#[test]
fn the_english_wordlist_verifies() {
    assert!(verify_english_wordlist());
}
