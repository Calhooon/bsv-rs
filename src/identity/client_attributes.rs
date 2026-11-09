//! The reference wallet's attribute matcher (#751): `filterCertificatesByAttributes`
//! (`ts-stack@edf6e03`
//! `packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:140-293`,
//! called by `discoverByAttributes` at `Wallet.ts:1078`), function for
//! function over a certificate's `decrypted_fields`, so a host answering an
//! attribute question with a certificate that does not carry the asked values
//! is not believed. `userName` is matched exactly after
//! `normalizeIdentitySearch` (`:141`, `:214-215`), every other named field by
//! `identityFuzzyMatches` (`:145-162`: the tokens found in order on one line,
//! each a literal under JavaScript's `gi` without `u`), `any` across every
//! string field but `profilePhoto` and `icon` (`:229-244`: two UTF-16 units
//! fuzzily, three or more by `identityTextMatches`, `:166-223`: NFD, `\p{Mn}`
//! removed, lower case, the English stop words, `-term`, a quoted phrase), and
//! nothing kept when no attribute is usable (`:257-265`, `:291`). Language
//! stemming is not the reference's either (`:190-194`). JavaScript's case
//! mapping, white space and `trim` are written out here; the case tables are
//! Rust's Unicode version, where the reference's are V8's (a stated residue).
//!
//! Also `query`'s filter (#746): a certificate is kept only when it matches
//! every field its question carries, the attributes since #751.

use crate::identity::types::{IdentityCertificate, IdentityQuery};
use indexmap::IndexMap;
use regex::Regex;
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;

/// The fields `any` does not search (`identityUtils.ts:229`).
const UNSEARCHABLE: [&str; 2] = ["profilePhoto", "icon"];

/// The reference's `IDENTITY_STOP_WORDS` (`identityUtils.ts:166-167`), each
/// word between two spaces, read by `includes(' token ')`.
const STOP_WORDS: &str = " a about above after again against all am an and any are aren't as at be because been before being below between both but by can't cannot could couldn't did didn't do does doesn't doing don't down during each few for from further had hadn't has hasn't have haven't having he he'd he'll he's her here here's hers herself him himself his how how's i i'd i'll i'm i've if in into is isn't it it's its itself let's me more most mustn't my myself no nor not of off on once only or other ought our ours ourselves out over own same shan't she she'd she'll she's should shouldn't so some such than that that's the their theirs them themselves then there there's these they they'd they'll they're they've this those through to too under until up very was wasn't we we'd we'll we're we've were weren't what what's when when's where where's which while who who's whom why why's with won't would wouldn't you you'd you'll you're you've your yours yourself yourselves ";

/// Whether `cert` is one `query` asked for (#746, #751): the subject through
/// `is_asked_subject`, the type's canonical text exactly, the certifier's key
/// lower-cased against the asked text lower-cased, the attributes by
/// [`keeps`] over the decrypted fields; a field the question does not carry
/// filters nothing.
pub(super) fn is_asked(cert: &IdentityCertificate, query: &IdentityQuery) -> bool {
    let verifiable = &cert.certificate;
    query
        .identity_key
        .as_deref()
        .is_none_or(|key| super::client::is_asked_subject(verifiable.subject(), key))
        && query
            .certificate_type
            .as_deref()
            .is_none_or(|cert_type| verifiable.type_base64() == cert_type)
        && query
            .certifier
            .as_deref()
            .is_none_or(|certifier| verifiable.certifier().to_hex() == certifier.to_lowercase())
        && query
            .attributes
            .as_ref()
            .is_none_or(|attributes| keeps(attributes, &cert.decrypted_fields))
}

/// `filterCertificatesByAttributes` for one certificate (`identityUtils.ts:283-293`):
/// `any` present, its search alone (`:275`; the other names unread);
/// otherwise every attribute whose value normalizes to text (`:257-265`)
/// matched by the field of its name, and none usable keeps nothing (`:291`).
pub(super) fn keeps(
    attributes: &IndexMap<String, String>,
    fields: &IndexMap<String, String>,
) -> bool {
    if let Some(any) = attributes.get("any") {
        return any_matches(fields, any);
    }
    let mut usable = attributes
        .iter()
        .filter(|(_, value)| !normalize(value).is_empty())
        .peekable();
    usable.peek().is_some()
        && usable.all(|(name, expected)| {
            fields
                .get(name)
                .is_some_and(|actual| attribute_matches(name, actual, expected))
        })
}

/// `identityAttributeMatches` (`identityUtils.ts:212-216`).
fn attribute_matches(name: &str, actual: &str, expected: &str) -> bool {
    if name == "userName" {
        return actual == normalize(expected);
    }
    fuzzy_matches(actual, expected)
}

/// JavaScript's `WhiteSpace` and `LineTerminator`, its `\s` and `trim`.
fn is_js_space(c: char) -> bool {
    super::reveal::is_js_whitespace(c)
}

/// `normalizeIdentitySearch` (`identityUtils.ts:140-142`): trimmed, each run
/// of white space one space.
fn normalize(input: &str) -> String {
    input
        .split(is_js_space)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The reference's `/\r\n?|\n| | /` split (`identityUtils.ts:147`).
fn lines(text: &str) -> Vec<Vec<u16>> {
    let mut lines = vec![Vec::new()];
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if matches!(c, '\r' | '\n' | '\u{2028}' | '\u{2029}') {
            if c == '\r' && chars.peek() == Some(&'\n') {
                chars.next();
            }
            lines.push(Vec::new());
        } else if let Some(line) = lines.last_mut() {
            let mut units = [0u16; 2];
            line.extend_from_slice(c.encode_utf16(&mut units));
        }
    }
    lines
}

/// ECMA-262's `Canonicalize` for a regular expression with `i` and without
/// `u`: a code unit's upper case when it is one code unit, never mapping a
/// unit above ASCII into ASCII.
fn canonical(unit: u16) -> u16 {
    let Some(c) = char::from_u32(u32::from(unit)) else {
        return unit;
    };
    let mut upper = c.to_uppercase();
    let (Some(mapped), None) = (upper.next(), upper.next()) else {
        return unit;
    };
    let mut units = [0u16; 2];
    match mapped.encode_utf16(&mut units) {
        [only] if unit < 128 || *only >= 128 => *only,
        _ => unit,
    }
}

/// `identityFuzzyMatches` (`identityUtils.ts:145-162`): on some line, every
/// token of the normalized expectation found in order, each search starting
/// where the last match ended.
fn fuzzy_matches(actual: &str, expected: &str) -> bool {
    let tokens: Vec<Vec<u16>> = normalize(expected)
        .split(' ')
        .map(|token| token.encode_utf16().map(canonical).collect())
        .collect();
    lines(actual).iter().any(|line| {
        let line: Vec<u16> = line.iter().copied().map(canonical).collect();
        let mut cursor = 0;
        tokens.iter().all(|token| {
            let found = (cursor..=line.len().saturating_sub(token.len()))
                .find(|&at| line.get(at..at + token.len()) == Some(token.as_slice()));
            found.inspect(|at| cursor = at + token.len()).is_some()
        })
    })
}

/// `identityAnyMatches` (`identityUtils.ts:229-244`).
fn any_matches(fields: &IndexMap<String, String>, expected: &str) -> bool {
    let normalized = normalize(expected);
    let units = normalized.encode_utf16().count();
    if units < 2 {
        return false;
    }
    let searchable = js_order(fields)
        .into_iter()
        .filter(|(name, _)| !UNSEARCHABLE.contains(name))
        .map(|(_, value)| value)
        .collect::<Vec<_>>()
        .join(" ");
    if units == 2 {
        return fuzzy_matches(&searchable, &normalized);
    }
    text_matches(&searchable, &normalized)
}

/// The order `Object.entries` walks a JavaScript object built in `fields`'
/// order: array-index names ahead, ascending, then the rest as inserted.
pub(super) fn js_order(fields: &IndexMap<String, String>) -> Vec<(&str, &str)> {
    let index = |name: &str| {
        name.parse::<u32>()
            .ok()
            .filter(|n| *n != u32::MAX && n.to_string() == name)
    };
    let mut entries: Vec<_> = fields
        .iter()
        .map(|(name, value)| (index(name), name.as_str(), value.as_str()))
        .collect();
    entries.sort_by_key(|(index, _, _)| index.map_or((1, 0), |n| (0, n)));
    entries
        .into_iter()
        .map(|(_, name, value)| (name, value))
        .collect()
}

/// A compiled pattern of this module, `None` never in practice (the patterns
/// are constants; a failure keeps nothing rather than panics).
fn pattern(cell: &'static OnceLock<Option<Regex>>, text: &str) -> Option<&'static Regex> {
    cell.get_or_init(|| Regex::new(text).ok()).as_ref()
}

/// `foldIdentityText` (`identityUtils.ts:218-223`): NFD, nonspacing marks
/// removed, lower case.
fn fold(input: &str) -> String {
    static MARKS: OnceLock<Option<Regex>> = OnceLock::new();
    let decomposed: String = input.nfd().collect();
    match pattern(&MARKS, r"\p{Mn}") {
        Some(marks) => marks.replace_all(&decomposed, "").to_lowercase(),
        None => decomposed.to_lowercase(),
    }
}

/// `identityTextTokens` (`identityUtils.ts:169-174`): the runs of characters
/// outside Dash, Pattern_Syntax, Quotation_Mark, Terminal_Punctuation and
/// White_Space (the apostrophe kept), less the stop words.
fn text_tokens(text: &str) -> Vec<&str> {
    static TOKENS: OnceLock<Option<Regex>> = OnceLock::new();
    let Some(tokens) = pattern(
        &TOKENS,
        r"(?:[^\p{Dash}\p{Pattern_Syntax}\p{Quotation_Mark}\p{Terminal_Punctuation}\p{White_Space}]|')+",
    ) else {
        return Vec::new();
    };
    tokens
        .find_iter(text)
        .map(|found| found.as_str())
        .filter(|token| !STOP_WORDS.contains(&format!(" {token} ")))
        .collect()
}

/// The parts of a folded query as `/-?"([^"]*)"|[^\s"]+/g` finds them
/// (`identityUtils.ts:199`): the whole part and its phrase, if quoted.
fn query_parts(query: &str) -> Vec<(&str, Option<&str>)> {
    let closing = |from: usize| query.get(from..).and_then(|rest| rest.find('"'));
    let mut parts = Vec::new();
    let mut at = 0;
    while let Some(c) = query.get(at..).and_then(|rest| rest.chars().next()) {
        let open = if c == '-' && query[at + 1..].starts_with('"') {
            at + 1
        } else {
            at
        };
        if query[open..].starts_with('"') {
            if let Some(length) = closing(open + 1) {
                let end = open + 1 + length;
                parts.push((&query[at..=end], Some(&query[open + 1..end])));
                at = end + 1;
                continue;
            }
        }
        let run = query[at..]
            .find(|c: char| is_js_space(c) || c == '"')
            .unwrap_or(query.len() - at);
        if run == 0 {
            at += c.len_utf8();
        } else {
            parts.push((&query[at..at + run], None));
            at += run;
        }
    }
    parts
}

/// `identityQueryPartMatch` (`identityUtils.ts:177-188`): -1 refuses, 1 a
/// positive term, 0 neutral.
fn part_match(tokens: &[&str], text: &str, raw: &str, phrase: Option<&str>) -> i8 {
    let negative = raw.starts_with('-') && raw.len() > 1;
    if let Some(phrase) = phrase {
        if text.contains(phrase) == negative {
            return -1;
        }
        if negative {
            return 0;
        }
    }
    let source = phrase.unwrap_or(if negative { &raw[1..] } else { raw });
    if !text_tokens(source).iter().any(|term| tokens.contains(term)) {
        return 0;
    }
    if negative {
        -1
    } else {
        1
    }
}

/// `identityTextMatches` (`identityUtils.ts:195-209`): no part refusing and
/// one positive.
fn text_matches(searchable: &str, search: &str) -> bool {
    let text = fold(searchable);
    let query = fold(search);
    let tokens = text_tokens(&text);
    let mut positive = false;
    for (raw, phrase) in query_parts(&query) {
        match part_match(&tokens, &text, raw, phrase) {
            -1 => return false,
            1 => positive = true,
            _ => {}
        }
    }
    positive
}

#[cfg(test)]
#[path = "client_attributes_751_tests.rs"]
mod tests_751;
