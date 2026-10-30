//! The reference's identity search and ISO date predicates, including literal token order.

use super::{invalid, Object, Result};
use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;
use unicode_normalization::UnicodeNormalization;

const STOP_WORDS: &str = " a about above after again against all am an and any are aren't as at be because been before being below between both but by can't cannot could couldn't did didn't do does doesn't doing don't down during each few for from further had hadn't has hasn't have haven't having he he'd he'll he's her here here's hers herself him himself his how how's i i'd i'll i'm i've if in into is isn't it it's its itself let's me more most mustn't my myself no nor not of off on once only or other ought our ours ourselves out over own same shan't she she'd she'll she's should shouldn't so some such than that that's the their theirs them themselves then there there's these they they'd they'll they're they've this those through to too under until up very was wasn't we we'd we'll we're we've were weren't what what's when when's where where's which while who who's whom why why's with won't would wouldn't you you'd you'll you're you've your yours yourself yourselves ";

fn compile(pattern: &str) -> Result<Regex> {
    Regex::new(pattern)
        .map_err(|e| crate::Error::WalletError(format!("identity result pattern: {e}")))
}

// LazyLock is available below the declared Rust 1.88 minimum.
static SPACE: LazyLock<Result<Regex>> = LazyLock::new(|| {
    compile(
        r"[\t\n\v\f\r \u{00a0}\u{1680}\u{2000}-\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}\u{feff}]+",
    )
});
static MARKS: LazyLock<Result<Regex>> = LazyLock::new(|| compile(r"\p{Mn}"));
static TOKENS: LazyLock<Result<Regex>> = LazyLock::new(|| {
    compile(
        r"(?:[^\p{Dash}\p{Pattern_Syntax}\p{Quotation_Mark}\p{Terminal_Punctuation}\p{White_Space}]|')+",
    )
});
static PARTS: LazyLock<Result<Regex>> = LazyLock::new(|| compile(r#"-?"([^"]*)"|[^ "]+"#));
fn expression(pattern: &'static LazyLock<Result<Regex>>) -> Result<&'static Regex> {
    pattern.as_ref().map_err(Clone::clone)
}

fn normalized(text: &str) -> Result<String> {
    // ECMAScript \s includes BOM and excludes U+0085.
    Ok(expression(&SPACE)?
        .replace_all(text, " ")
        .trim_matches(' ')
        .to_string())
}

fn fold(text: &str) -> Result<String> {
    let decomposed: String = text.nfd().collect();
    Ok(expression(&MARKS)?
        .replace_all(&decomposed, "")
        .to_lowercase())
}

// RegExp /i without /u canonicalizes single UTF-16 code units. It does not
// fold a non-ASCII unit onto ASCII (the Kelvin sign and long s are distinct).
fn literal_case(text: &str) -> String {
    text.chars()
        .map(|c| {
            let mut upper = c.to_uppercase();
            let mapped = upper.next().unwrap_or(c);
            if c.len_utf16() != 1 || upper.next().is_some() || (!c.is_ascii() && mapped.is_ascii())
            {
                c
            } else {
                mapped
            }
        })
        .collect()
}

fn fuzzy(actual: &str, expected: &str) -> Result<bool> {
    let tokens = normalized(expected)?;
    let tokens: Vec<_> = tokens.split(' ').map(literal_case).collect();
    for line in actual.split(['\r', '\n', '\u{2028}', '\u{2029}']) {
        let line = literal_case(line);
        let mut remaining = line.as_str();
        let mut matched = true;
        for token in &tokens {
            if let Some(index) = remaining.find(token) {
                remaining = &remaining[index + token.len()..];
            } else {
                matched = false;
                break;
            }
        }
        if matched {
            return Ok(true);
        }
    }
    Ok(false)
}

fn tokens(text: &str) -> Result<Vec<String>> {
    let pattern = expression(&TOKENS)?;
    Ok(pattern
        .find_iter(text)
        .map(|m| m.as_str())
        .filter(|s| !STOP_WORDS.contains(&format!(" {s} ")))
        .map(str::to_owned)
        .collect())
}

fn text_matches(searchable: &str, search: &str) -> Result<bool> {
    let text = fold(searchable)?;
    let query = fold(search)?;
    let indexed = tokens(&text)?;
    let parts = expression(&PARTS)?;
    let mut positive = false;
    for part in parts.captures_iter(&query) {
        let Some(raw) = part.get(0).map(|m| m.as_str()) else {
            continue;
        };
        let phrase = part.get(1).map(|m| m.as_str());
        let negative = raw.starts_with('-') && raw.len() > 1;
        if let Some(phrase) = phrase {
            let present = text.contains(phrase);
            if (negative && present) || (!negative && !present) {
                return Ok(false);
            }
            if negative {
                continue;
            }
        }
        let terms = tokens(phrase.unwrap_or_else(|| if negative { &raw[1..] } else { raw }))?;
        let matched = terms.iter().any(|t| indexed.contains(t));
        if negative && matched {
            return Ok(false);
        }
        positive |= matched && !negative;
    }
    Ok(positive)
}

pub(super) fn bind(fields: &Object<'_>, request: &Value, call: &str, field: &str) -> Result<()> {
    let Some(attributes) = request["attributes"].as_object() else {
        return Ok(());
    };
    let actual: indexmap::IndexMap<String, String> = fields
        .iter()
        .filter_map(|(k, v)| serde_json::from_str(v.get()).ok().map(|v| (k.clone(), v)))
        .collect();
    if let Some(expected) = attributes.get("any") {
        if !any_matches(&actual, expected)? {
            return Err(invalid(
                call,
                &format!("{field}.decryptedFields"),
                "a match for the requested any attribute",
            ));
        }
        return Ok(());
    }
    let mut usable = 0;
    for key in super::request_keys(request, "attributes") {
        let expected = &attributes[key];
        let expected = expected
            .as_str()
            .ok_or_else(|| invalid(call, &format!("request.attributes.{key}"), "a string"))?;
        let normalized = normalized(expected)?;
        if normalized.is_empty() {
            continue;
        }
        usable += 1;
        let matched = match actual.get(key) {
            None => false,
            Some(actual) if key == "userName" => *actual == normalized,
            Some(actual) => fuzzy(actual, expected)?,
        };
        if !matched {
            return Err(invalid(
                call,
                &format!("{field}.decryptedFields.{key}"),
                "the requested public attribute",
            ));
        }
    }
    if usable == 0 {
        return Err(invalid(
            call,
            &format!("{field}.decryptedFields"),
            "a usable requested attribute",
        ));
    }
    Ok(())
}

fn any_matches(fields: &indexmap::IndexMap<String, String>, expected: &Value) -> Result<bool> {
    let Some(expected) = expected.as_str() else {
        return Ok(false);
    };
    let normalized = normalized(expected)?;
    let length = normalized.encode_utf16().count();
    if length < 2 {
        return Ok(false);
    }
    let mut searchable = String::new();
    for (name, value) in fields {
        if matches!(name.as_str(), "profilePhoto" | "icon") {
            continue;
        }
        if !searchable.is_empty() {
            searchable.push(' ');
        }
        searchable.push_str(value);
    }
    if length == 2 {
        fuzzy(&searchable, &normalized)
    } else {
        text_matches(&searchable, &normalized)
    }
}
