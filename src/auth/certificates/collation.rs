//! The reference's field-name order (#249).
//!
//! The reference serializer sorts a certificate's field names with
//! `a.localeCompare(b)` and no locale or options (`ts-stack@edf6e03`
//! `Certificate.ts:282`): under Node's default ICU data and an `en` or root
//! locale, the Unicode Collation Algorithm at tertiary strength over the
//! CLDR root order, punctuation non-ignorable. This module carries that order
//! for U+0000..U+00FF (ASCII and Latin-1): the DUCET rows of those code
//! points and of the two contractions inside the range (`l` and `L` before
//! U+00B7), each level's weights ranked densely by
//! `tests/support/certificate_collation_table_249.mjs`. The comparison is
//! the algorithm's: every primary weight of both names, then every
//! secondary, then every tertiary; names equal at all three (they differ
//! only in a control character other than U+0009..U+000D and U+0085, which
//! carries no weight) fall back to their bytes, where the reference keeps
//! its key list's order.
//!
//! The residual: a character above U+00FF gets a primary weight past every
//! weight in the table, in code point order, with no secondary or tertiary
//! difference. That is ICU's order for none of them in general (a combining
//! mark is a secondary weight there, a Latin letter outside Latin-1 sorts
//! with its base letter), so a name carrying one may be ordered otherwise
//! than the reference orders it; a received certificate is verified over
//! its own bytes and is not affected (#249).

/// One collation element: primary, secondary, tertiary (0 = no weight).
type Element = (u8, u8, u8);

/// The largest primary weight in [`TABLE`].
const MAX_PRIMARY: u32 = 101;

/// U+0000..=U+00FF to their collation elements, each row led by its code
/// point.
#[rustfmt::skip]
static TABLE: [(u8, &[Element]); 256] = [
    // @version 13.0.0; primaries 101, secondaries 10, tertiaries 7
    (0x00, &[(0, 0, 0)]), // control
    (0x01, &[(0, 0, 0)]), // control
    (0x02, &[(0, 0, 0)]), // control
    (0x03, &[(0, 0, 0)]), // control
    (0x04, &[(0, 0, 0)]), // control
    (0x05, &[(0, 0, 0)]), // control
    (0x06, &[(0, 0, 0)]), // control
    (0x07, &[(0, 0, 0)]), // control
    (0x08, &[(0, 0, 0)]), // control
    (0x09, &[(1, 1, 1)]), // control
    (0x0A, &[(2, 1, 1)]), // control
    (0x0B, &[(3, 1, 1)]), // control
    (0x0C, &[(4, 1, 1)]), // control
    (0x0D, &[(5, 1, 1)]), // control
    (0x0E, &[(0, 0, 0)]), // control
    (0x0F, &[(0, 0, 0)]), // control
    (0x10, &[(0, 0, 0)]), // control
    (0x11, &[(0, 0, 0)]), // control
    (0x12, &[(0, 0, 0)]), // control
    (0x13, &[(0, 0, 0)]), // control
    (0x14, &[(0, 0, 0)]), // control
    (0x15, &[(0, 0, 0)]), // control
    (0x16, &[(0, 0, 0)]), // control
    (0x17, &[(0, 0, 0)]), // control
    (0x18, &[(0, 0, 0)]), // control
    (0x19, &[(0, 0, 0)]), // control
    (0x1A, &[(0, 0, 0)]), // control
    (0x1B, &[(0, 0, 0)]), // control
    (0x1C, &[(0, 0, 0)]), // control
    (0x1D, &[(0, 0, 0)]), // control
    (0x1E, &[(0, 0, 0)]), // control
    (0x1F, &[(0, 0, 0)]), // control
    (0x20, &[(7, 1, 1)]), // " "
    (0x21, &[(13, 1, 1)]), // "!"
    (0x22, &[(20, 1, 1)]), // "\""
    (0x23, &[(36, 1, 1)]), // "#"
    (0x24, &[(61, 1, 1)]), // "$"
    (0x25, &[(37, 1, 1)]), // "%"
    (0x26, &[(35, 1, 1)]), // "&"
    (0x27, &[(19, 1, 1)]), // "'"
    (0x28, &[(23, 1, 1)]), // "("
    (0x29, &[(24, 1, 1)]), // ")"
    (0x2A, &[(32, 1, 1)]), // "*"
    (0x2B, &[(47, 1, 1)]), // "+"
    (0x2C, &[(10, 1, 1)]), // ","
    (0x2D, &[(9, 1, 1)]), // "-"
    (0x2E, &[(17, 1, 1)]), // "."
    (0x2F, &[(33, 1, 1)]), // "/"
    (0x30, &[(64, 1, 1)]), // "0"
    (0x31, &[(65, 1, 1)]), // "1"
    (0x32, &[(66, 1, 1)]), // "2"
    (0x33, &[(67, 1, 1)]), // "3"
    (0x34, &[(68, 1, 1)]), // "4"
    (0x35, &[(69, 1, 1)]), // "5"
    (0x36, &[(70, 1, 1)]), // "6"
    (0x37, &[(71, 1, 1)]), // "7"
    (0x38, &[(72, 1, 1)]), // "8"
    (0x39, &[(73, 1, 1)]), // "9"
    (0x3A, &[(12, 1, 1)]), // ":"
    (0x3B, &[(11, 1, 1)]), // ";"
    (0x3C, &[(51, 1, 1)]), // "<"
    (0x3D, &[(52, 1, 1)]), // "="
    (0x3E, &[(53, 1, 1)]), // ">"
    (0x3F, &[(15, 1, 1)]), // "?"
    (0x40, &[(31, 1, 1)]), // "@"
    (0x41, &[(74, 1, 3)]), // "A"
    (0x42, &[(75, 1, 3)]), // "B"
    (0x43, &[(76, 1, 3)]), // "C"
    (0x44, &[(77, 1, 3)]), // "D"
    (0x45, &[(78, 1, 3)]), // "E"
    (0x46, &[(79, 1, 3)]), // "F"
    (0x47, &[(80, 1, 3)]), // "G"
    (0x48, &[(81, 1, 3)]), // "H"
    (0x49, &[(82, 1, 3)]), // "I"
    (0x4A, &[(83, 1, 3)]), // "J"
    (0x4B, &[(84, 1, 3)]), // "K"
    (0x4C, &[(85, 1, 3)]), // "L"
    (0x4D, &[(86, 1, 3)]), // "M"
    (0x4E, &[(87, 1, 3)]), // "N"
    (0x4F, &[(88, 1, 3)]), // "O"
    (0x50, &[(89, 1, 3)]), // "P"
    (0x51, &[(90, 1, 3)]), // "Q"
    (0x52, &[(91, 1, 3)]), // "R"
    (0x53, &[(92, 1, 3)]), // "S"
    (0x54, &[(93, 1, 3)]), // "T"
    (0x55, &[(94, 1, 3)]), // "U"
    (0x56, &[(95, 1, 3)]), // "V"
    (0x57, &[(96, 1, 3)]), // "W"
    (0x58, &[(97, 1, 3)]), // "X"
    (0x59, &[(98, 1, 3)]), // "Y"
    (0x5A, &[(99, 1, 3)]), // "Z"
    (0x5B, &[(25, 1, 1)]), // "["
    (0x5C, &[(34, 1, 1)]), // "\\"
    (0x5D, &[(26, 1, 1)]), // "]"
    (0x5E, &[(40, 1, 1)]), // "^"
    (0x5F, &[(8, 1, 1)]), // "_"
    (0x60, &[(38, 1, 1)]), // "`"
    (0x61, &[(74, 1, 1)]), // "a"
    (0x62, &[(75, 1, 1)]), // "b"
    (0x63, &[(76, 1, 1)]), // "c"
    (0x64, &[(77, 1, 1)]), // "d"
    (0x65, &[(78, 1, 1)]), // "e"
    (0x66, &[(79, 1, 1)]), // "f"
    (0x67, &[(80, 1, 1)]), // "g"
    (0x68, &[(81, 1, 1)]), // "h"
    (0x69, &[(82, 1, 1)]), // "i"
    (0x6A, &[(83, 1, 1)]), // "j"
    (0x6B, &[(84, 1, 1)]), // "k"
    (0x6C, &[(85, 1, 1)]), // "l"
    (0x6D, &[(86, 1, 1)]), // "m"
    (0x6E, &[(87, 1, 1)]), // "n"
    (0x6F, &[(88, 1, 1)]), // "o"
    (0x70, &[(89, 1, 1)]), // "p"
    (0x71, &[(90, 1, 1)]), // "q"
    (0x72, &[(91, 1, 1)]), // "r"
    (0x73, &[(92, 1, 1)]), // "s"
    (0x74, &[(93, 1, 1)]), // "t"
    (0x75, &[(94, 1, 1)]), // "u"
    (0x76, &[(95, 1, 1)]), // "v"
    (0x77, &[(96, 1, 1)]), // "w"
    (0x78, &[(97, 1, 1)]), // "x"
    (0x79, &[(98, 1, 1)]), // "y"
    (0x7A, &[(99, 1, 1)]), // "z"
    (0x7B, &[(27, 1, 1)]), // "{"
    (0x7C, &[(55, 1, 1)]), // "|"
    (0x7D, &[(28, 1, 1)]), // "}"
    (0x7E, &[(57, 1, 1)]), // "~"
    (0x7F, &[(0, 0, 0)]), // control
    (0x80, &[(0, 0, 0)]), // control
    (0x81, &[(0, 0, 0)]), // control
    (0x82, &[(0, 0, 0)]), // control
    (0x83, &[(0, 0, 0)]), // control
    (0x84, &[(0, 0, 0)]), // control
    (0x85, &[(6, 1, 1)]), // control
    (0x86, &[(0, 0, 0)]), // control
    (0x87, &[(0, 0, 0)]), // control
    (0x88, &[(0, 0, 0)]), // control
    (0x89, &[(0, 0, 0)]), // control
    (0x8A, &[(0, 0, 0)]), // control
    (0x8B, &[(0, 0, 0)]), // control
    (0x8C, &[(0, 0, 0)]), // control
    (0x8D, &[(0, 0, 0)]), // control
    (0x8E, &[(0, 0, 0)]), // control
    (0x8F, &[(0, 0, 0)]), // control
    (0x90, &[(0, 0, 0)]), // control
    (0x91, &[(0, 0, 0)]), // control
    (0x92, &[(0, 0, 0)]), // control
    (0x93, &[(0, 0, 0)]), // control
    (0x94, &[(0, 0, 0)]), // control
    (0x95, &[(0, 0, 0)]), // control
    (0x96, &[(0, 0, 0)]), // control
    (0x97, &[(0, 0, 0)]), // control
    (0x98, &[(0, 0, 0)]), // control
    (0x99, &[(0, 0, 0)]), // control
    (0x9A, &[(0, 0, 0)]), // control
    (0x9B, &[(0, 0, 0)]), // control
    (0x9C, &[(0, 0, 0)]), // control
    (0x9D, &[(0, 0, 0)]), // control
    (0x9E, &[(0, 0, 0)]), // control
    (0x9F, &[(0, 0, 0)]), // control
    (0xA0, &[(7, 1, 6)]), // " "
    (0xA1, &[(14, 1, 1)]), // "¡"
    (0xA2, &[(60, 1, 1)]), // "¢"
    (0xA3, &[(62, 1, 1)]), // "£"
    (0xA4, &[(59, 1, 1)]), // "¤"
    (0xA5, &[(63, 1, 1)]), // "¥"
    (0xA6, &[(56, 1, 1)]), // "¦"
    (0xA7, &[(29, 1, 1)]), // "§"
    (0xA8, &[(42, 1, 1)]), // "¨"
    (0xA9, &[(45, 1, 1)]), // "©"
    (0xAA, &[(74, 1, 5)]), // "ª"
    (0xAB, &[(21, 1, 1)]), // "«"
    (0xAC, &[(54, 1, 1)]), // "¬"
    (0xAD, &[(0, 0, 0)]), // "­"
    (0xAE, &[(46, 1, 1)]), // "®"
    (0xAF, &[(41, 1, 1)]), // "¯"
    (0xB0, &[(44, 1, 1)]), // "°"
    (0xB1, &[(48, 1, 1)]), // "±"
    (0xB2, &[(66, 1, 5)]), // "²"
    (0xB3, &[(67, 1, 5)]), // "³"
    (0xB4, &[(39, 1, 1)]), // "´"
    (0xB5, &[(101, 1, 2)]), // "µ"
    (0xB6, &[(30, 1, 1)]), // "¶"
    (0xB7, &[(18, 1, 1)]), // "·"
    (0xB8, &[(43, 1, 1)]), // "¸"
    (0xB9, &[(65, 1, 5)]), // "¹"
    (0xBA, &[(88, 1, 5)]), // "º"
    (0xBB, &[(22, 1, 1)]), // "»"
    (0xBC, &[(65, 1, 7), (58, 1, 7), (68, 1, 7)]), // "¼"
    (0xBD, &[(65, 1, 7), (58, 1, 7), (66, 1, 7)]), // "½"
    (0xBE, &[(67, 1, 7), (58, 1, 7), (68, 1, 7)]), // "¾"
    (0xBF, &[(16, 1, 1)]), // "¿"
    (0xC0, &[(74, 1, 3), (0, 3, 1)]), // "À"
    (0xC1, &[(74, 1, 3), (0, 2, 1)]), // "Á"
    (0xC2, &[(74, 1, 3), (0, 4, 1)]), // "Â"
    (0xC3, &[(74, 1, 3), (0, 7, 1)]), // "Ã"
    (0xC4, &[(74, 1, 3), (0, 6, 1)]), // "Ä"
    (0xC5, &[(74, 1, 3), (0, 5, 1)]), // "Å"
    (0xC6, &[(74, 1, 4), (0, 10, 2), (78, 1, 4)]), // "Æ"
    (0xC7, &[(76, 1, 3), (0, 9, 1)]), // "Ç"
    (0xC8, &[(78, 1, 3), (0, 3, 1)]), // "È"
    (0xC9, &[(78, 1, 3), (0, 2, 1)]), // "É"
    (0xCA, &[(78, 1, 3), (0, 4, 1)]), // "Ê"
    (0xCB, &[(78, 1, 3), (0, 6, 1)]), // "Ë"
    (0xCC, &[(82, 1, 3), (0, 3, 1)]), // "Ì"
    (0xCD, &[(82, 1, 3), (0, 2, 1)]), // "Í"
    (0xCE, &[(82, 1, 3), (0, 4, 1)]), // "Î"
    (0xCF, &[(82, 1, 3), (0, 6, 1)]), // "Ï"
    (0xD0, &[(77, 1, 4), (0, 10, 2)]), // "Ð"
    (0xD1, &[(87, 1, 3), (0, 7, 1)]), // "Ñ"
    (0xD2, &[(88, 1, 3), (0, 3, 1)]), // "Ò"
    (0xD3, &[(88, 1, 3), (0, 2, 1)]), // "Ó"
    (0xD4, &[(88, 1, 3), (0, 4, 1)]), // "Ô"
    (0xD5, &[(88, 1, 3), (0, 7, 1)]), // "Õ"
    (0xD6, &[(88, 1, 3), (0, 6, 1)]), // "Ö"
    (0xD7, &[(50, 1, 1)]), // "×"
    (0xD8, &[(88, 1, 3), (0, 8, 1)]), // "Ø"
    (0xD9, &[(94, 1, 3), (0, 3, 1)]), // "Ù"
    (0xDA, &[(94, 1, 3), (0, 2, 1)]), // "Ú"
    (0xDB, &[(94, 1, 3), (0, 4, 1)]), // "Û"
    (0xDC, &[(94, 1, 3), (0, 6, 1)]), // "Ü"
    (0xDD, &[(98, 1, 3), (0, 2, 1)]), // "Ý"
    (0xDE, &[(100, 1, 3)]), // "Þ"
    (0xDF, &[(92, 1, 2), (0, 10, 2), (92, 1, 2)]), // "ß"
    (0xE0, &[(74, 1, 1), (0, 3, 1)]), // "à"
    (0xE1, &[(74, 1, 1), (0, 2, 1)]), // "á"
    (0xE2, &[(74, 1, 1), (0, 4, 1)]), // "â"
    (0xE3, &[(74, 1, 1), (0, 7, 1)]), // "ã"
    (0xE4, &[(74, 1, 1), (0, 6, 1)]), // "ä"
    (0xE5, &[(74, 1, 1), (0, 5, 1)]), // "å"
    (0xE6, &[(74, 1, 2), (0, 10, 2), (78, 1, 2)]), // "æ"
    (0xE7, &[(76, 1, 1), (0, 9, 1)]), // "ç"
    (0xE8, &[(78, 1, 1), (0, 3, 1)]), // "è"
    (0xE9, &[(78, 1, 1), (0, 2, 1)]), // "é"
    (0xEA, &[(78, 1, 1), (0, 4, 1)]), // "ê"
    (0xEB, &[(78, 1, 1), (0, 6, 1)]), // "ë"
    (0xEC, &[(82, 1, 1), (0, 3, 1)]), // "ì"
    (0xED, &[(82, 1, 1), (0, 2, 1)]), // "í"
    (0xEE, &[(82, 1, 1), (0, 4, 1)]), // "î"
    (0xEF, &[(82, 1, 1), (0, 6, 1)]), // "ï"
    (0xF0, &[(77, 1, 2), (0, 10, 2)]), // "ð"
    (0xF1, &[(87, 1, 1), (0, 7, 1)]), // "ñ"
    (0xF2, &[(88, 1, 1), (0, 3, 1)]), // "ò"
    (0xF3, &[(88, 1, 1), (0, 2, 1)]), // "ó"
    (0xF4, &[(88, 1, 1), (0, 4, 1)]), // "ô"
    (0xF5, &[(88, 1, 1), (0, 7, 1)]), // "õ"
    (0xF6, &[(88, 1, 1), (0, 6, 1)]), // "ö"
    (0xF7, &[(49, 1, 1)]), // "÷"
    (0xF8, &[(88, 1, 1), (0, 8, 1)]), // "ø"
    (0xF9, &[(94, 1, 1), (0, 3, 1)]), // "ù"
    (0xFA, &[(94, 1, 1), (0, 2, 1)]), // "ú"
    (0xFB, &[(94, 1, 1), (0, 4, 1)]), // "û"
    (0xFC, &[(94, 1, 1), (0, 6, 1)]), // "ü"
    (0xFD, &[(98, 1, 1), (0, 2, 1)]), // "ý"
    (0xFE, &[(100, 1, 1)]), // "þ"
    (0xFF, &[(98, 1, 1), (0, 6, 1)]), // "ÿ"
];

/// `l` before U+00B7 (DUCET `006C 00B7`).
const SMALL_L_MIDDLE_DOT: &[Element] = &[(85, 1, 1), (0, 10, 1)];
/// `L` before U+00B7 (DUCET `004C 00B7`).
const CAPITAL_L_MIDDLE_DOT: &[Element] = &[(85, 1, 3), (0, 10, 1)];

/// A name's sort key: its primary, secondary and tertiary weights in turn,
/// compared level by level.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SortKey {
    primary: Vec<u32>,
    secondary: Vec<u8>,
    tertiary: Vec<u8>,
}

impl SortKey {
    fn push(&mut self, (p, s, t): Element) {
        if p != 0 {
            self.primary.push(p as u32);
        }
        if s != 0 {
            self.secondary.push(s);
        }
        if t != 0 {
            self.tertiary.push(t);
        }
    }
}

/// The sort key of `name` under the reference's order.
pub(crate) fn sort_key(name: &str) -> SortKey {
    let mut key = SortKey {
        primary: Vec::with_capacity(name.len()),
        secondary: Vec::with_capacity(name.len()),
        tertiary: Vec::with_capacity(name.len()),
    };
    let mut chars = name.chars().peekable();
    while let Some(c) = chars.next() {
        let contraction = match c {
            'l' => Some(SMALL_L_MIDDLE_DOT),
            'L' => Some(CAPITAL_L_MIDDLE_DOT),
            _ => None,
        };
        if let Some(elements) = contraction.filter(|_| chars.peek() == Some(&'\u{b7}')) {
            chars.next();
            elements.iter().for_each(|&e| key.push(e));
            continue;
        }
        match TABLE.get(c as usize) {
            Some((_, elements)) => elements.iter().for_each(|&e| key.push(e)),
            // The residual: past the table, in code point order.
            None => {
                key.primary.push(MAX_PRIMARY + c as u32);
                key.secondary.push(1);
                key.tertiary.push(1);
            }
        }
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    /// Orders two field names as the reference's `localeCompare` does, within
    /// U+0000..=U+00FF; equal sort keys fall back to the bytes.
    fn reference_order(a: &str, b: &str) -> Ordering {
        sort_key(a)
            .cmp(&sort_key(b))
            .then_with(|| a.as_bytes().cmp(b.as_bytes()))
    }

    fn sorted(names: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        v.sort_by(|a, b| reference_order(a, b));
        v
    }

    #[test]
    fn every_row_of_the_table_is_its_own_code_point() {
        for (i, (code, _)) in TABLE.iter().enumerate() {
            assert_eq!(*code as usize, i);
        }
    }

    #[test]
    fn the_witness_names_sort_as_local_compare_sorts_them() {
        // Node v22.18.0, ICU 77.1: `localeCompare` gives this order; byte
        // order gives `Name, a0, a_b, age, f, éa`.
        assert_eq!(
            sorted(&["Name", "a_b", "age", "a0", "éa", "f"]),
            ["a_b", "a0", "age", "éa", "f", "Name"]
        );
    }

    #[test]
    fn case_is_tertiary_lower_first_and_accents_secondary() {
        assert_eq!(sorted(&["B", "a", "A", "b"]), ["a", "A", "b", "B"]);
        assert_eq!(sorted(&["ab", "Aa", "éa", "ea"]), ["Aa", "ab", "ea", "éa"]);
        assert_eq!(sorted(&["e", "E", "é", "É"]), ["e", "E", "é", "É"]);
    }

    #[test]
    fn expansions_and_the_middle_dot_contraction() {
        // ß is `ss` at the primary level, æ is `ae`.
        assert_eq!(sorted(&["st", "ß", "sr"]), ["sr", "ß", "st"]);
        assert_eq!(sorted(&["af", "æ", "ad"]), ["ad", "æ", "af"]);
        // `l·` is one letter l with a secondary mark, not l then a dot; a
        // tab is a primary weight, below every letter.
        assert_eq!(
            sorted(&["l\t", "L·", "l·", "lb", "lz", "k"]),
            ["k", "l·", "L·", "l\t", "lb", "lz"]
        );
    }

    #[test]
    fn a_weightless_control_character_ties_and_falls_back_to_bytes() {
        assert_eq!(reference_order("a\u{1}b", "ab"), Ordering::Less);
        assert_eq!(sort_key("a\u{1}b"), sort_key("ab"));
    }

    #[test]
    fn a_character_past_latin_1_sorts_after_the_table_in_code_point_order() {
        // The residual: ICU sorts U+0101 before `z`, with its base letter.
        assert_eq!(
            sorted(&["\u{3b1}", "z", "\u{101}"]),
            ["z", "\u{101}", "\u{3b1}"]
        );
    }
}
