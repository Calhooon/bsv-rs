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
//! `tests/support/certificate_collation_table_249.mjs`, which writes them to
//! `collation_latin1.txt`: the table is data, read at compile time, not
//! 256 rows of Rust. The comparison is
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

/// A code point's collation elements, padded with `(0, 0, 0)`, which adds
/// no weight: the longest expansion in the range (U+00BC..U+00BE, U+00C6,
/// U+00DF, U+00E6) is three elements.
type Row = [Element; 3];

/// The table: U+0000..=U+00FF, then the two contractions.
struct Table {
    rows: [Row; 256],
    /// `l` before U+00B7 (DUCET `006C 00B7`).
    small_l_middle_dot: Row,
    /// `L` before U+00B7 (DUCET `004C 00B7`).
    capital_l_middle_dot: Row,
    /// The largest primary weight in the table.
    max_primary: u8,
}

/// The table as data, not code: `collation_latin1.txt`, written by
/// `tests/support/certificate_collation_table_249.mjs`, parsed at compile
/// time as #89's wordlists are (`src/compat/bip39/wordlists/mod.rs`).
static TABLE: Table = parse(include_str!("collation_latin1.txt"));

/// The value of the hex digit `b`.
#[allow(clippy::panic)] // #249: called only from `parse`, in a static's initializer, so a panic is a compile error on the data file
const fn hex_digit(b: u8) -> u32 {
    match b {
        b'0'..=b'9' => (b - b'0') as u32,
        b'A'..=b'F' => (b - b'A' + 10) as u32,
        _ => panic!("a collation line's code point is not upper-case hex"),
    }
}

/// The four hex digits at `at` and the position after them.
const fn code_point(line: &[u8], at: usize) -> (u32, usize) {
    assert!(at + 4 <= line.len(), "a collation line is cut short");
    let mut v = 0;
    let mut i = at;
    while i < at + 4 {
        v = v * 16 + hex_digit(line[i]);
        i += 1;
    }
    (v, at + 4)
}

/// The decimal weight at `at`, at most 255, and the position after it.
const fn weight(line: &[u8], at: usize) -> (u8, usize) {
    let mut v: u32 = 0;
    let mut i = at;
    while i < line.len() && line[i].is_ascii_digit() {
        v = v * 10 + (line[i] - b'0') as u32;
        assert!(v <= 255, "a collation weight is above 255");
        i += 1;
    }
    assert!(i > at, "a collation weight is not a decimal number");
    (v as u8, i)
}

/// One to three space-separated elements `p.s.t` from `at` to the line's
/// end.
const fn elements(line: &[u8], mut at: usize) -> Row {
    let mut row = [(0, 0, 0); 3];
    let mut n = 0;
    while at < line.len() {
        assert!(
            line[at] == b' ',
            "collation elements are not space-separated"
        );
        assert!(n < 3, "a collation line has more than three elements");
        let (p, i) = weight(line, at + 1);
        assert!(
            i < line.len() && line[i] == b'.',
            "a collation element lacks its dots"
        );
        let (s, i) = weight(line, i + 1);
        assert!(
            i < line.len() && line[i] == b'.',
            "a collation element lacks its dots"
        );
        let (t, i) = weight(line, i + 1);
        row[n] = (p, s, t);
        n += 1;
        at = i;
    }
    assert!(n > 0, "a collation line has no element");
    row
}

/// The next LF-terminated line from `at`, as `(start, end)`, and the
/// position after its LF.
const fn next_line(text: &[u8], at: usize) -> (usize, usize, usize) {
    let mut end = at;
    while end < text.len() && text[end] != b'\n' {
        assert!(text[end] != b'\r', "a collation line carries a CR");
        end += 1;
    }
    assert!(end < text.len(), "a collation line is not LF-terminated");
    (at, end, end + 1)
}

/// Parses the table: `#` header lines, then 256 rows in code point order
/// (`00B7 18.1.1`), then `006C 00B7` and `004C 00B7` with their elements,
/// then the end. Evaluated in [`TABLE`]'s initializer, so a line out of
/// order or malformed is a compile error, never a runtime one.
const fn parse(text: &'static str) -> Table {
    let text = text.as_bytes();
    let mut at = 0;
    while at < text.len() && text[at] == b'#' {
        at = next_line(text, at).2;
    }
    let mut rows = [[(0, 0, 0); 3]; 256];
    let mut max_primary = 0;
    let mut c = 0;
    while c < 256 {
        let (start, end, next) = next_line(text, at);
        let line = text.split_at(end).0.split_at(start).1;
        let (cp, i) = code_point(line, 0);
        assert!(cp == c as u32, "a collation row is out of order");
        rows[c] = elements(line, i);
        let mut k = 0;
        while k < 3 {
            if rows[c][k].0 > max_primary {
                max_primary = rows[c][k].0;
            }
            k += 1;
        }
        at = next;
        c += 1;
    }
    let mut contractions = [[(0, 0, 0); 3]; 2];
    let expected = [(0x6C, 0xB7), (0x4C, 0xB7)];
    let mut k = 0;
    while k < 2 {
        let (start, end, next) = next_line(text, at);
        let line = text.split_at(end).0.split_at(start).1;
        let (a, i) = code_point(line, 0);
        assert!(
            i < line.len() && line[i] == b' ',
            "a contraction line is malformed"
        );
        let (b, i) = code_point(line, i + 1);
        assert!(
            a == expected[k].0 && b == expected[k].1,
            "the contractions are not 006C 00B7 then 004C 00B7"
        );
        contractions[k] = elements(line, i);
        at = next;
        k += 1;
    }
    assert!(
        at == text.len(),
        "the collation table has lines after the contractions"
    );
    Table {
        rows,
        small_l_middle_dot: contractions[0],
        capital_l_middle_dot: contractions[1],
        max_primary,
    }
}

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
            'l' => Some(&TABLE.small_l_middle_dot),
            'L' => Some(&TABLE.capital_l_middle_dot),
            _ => None,
        };
        if let Some(elements) = contraction.filter(|_| chars.peek() == Some(&'\u{b7}')) {
            chars.next();
            elements.iter().for_each(|&e| key.push(e));
            continue;
        }
        match TABLE.rows.get(c as usize) {
            Some(elements) => elements.iter().for_each(|&e| key.push(e)),
            // The residual: past the table, in code point order.
            None => {
                key.primary.push(TABLE.max_primary as u32 + c as u32);
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
