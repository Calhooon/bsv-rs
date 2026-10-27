//! The originator rule (#323): the reference's `validateOriginator`
//! (`ts-stack@edf6e03` `packages/sdk/src/wallet/validationHelpers.ts:996-1037`).
//!
//! An originator is a canonical DNS hostname with an optional port, trimmed
//! and lower-cased; the port is checked and dropped from the normalized
//! value, as BRC-100 wallet permissions are scoped to the hostname, not to a
//! TCP port. Every refusal is `WERR_INVALID_PARAMETER` in the reference's
//! words (`validateStringLength`'s at `:348-356` for the three lengths).

use crate::error::{Error, Result, WalletRefusalClass};

const CANONICAL: &str = "a canonical DNS hostname with an optional port";

/// Validates an originator as the reference's `validateOriginator` does.
///
/// `None` is accepted as `None`. Otherwise the text is trimmed and
/// lower-cased, 1 to 250 bytes, a hostname with an optional `:port` (1 to 5
/// ASCII digits, at most 65535), the hostname 1 to 250 bytes and each of its
/// dot-separated parts 1 to 63 bytes of `[a-z0-9]`, inner hyphens allowed.
/// The answer is the hostname without the port: `Example.COM:8080` is
/// `example.com`. A scheme (`https://example.com`) is refused, as the
/// reference refuses it: the colon reads as a port separator.
///
/// # Errors
///
/// [`Error::WalletRefusal`] of class [`WalletRefusalClass::InvalidParameter`]
/// in the reference's words, e.g. `The originator parameter must be a
/// canonical DNS hostname with an optional port`.
pub fn validate_originator(s: Option<&str>) -> Result<Option<String>> {
    let Some(s) = s else {
        return Ok(None);
    };
    let s = trim_js(s).to_lowercase();
    string_length(&s, "originator", 1, 250)?;
    let hostname = match s.rfind(':') {
        None => s.as_str(),
        Some(separator) => {
            if s.find(':') != Some(separator) || !is_port(&s[separator + 1..]) {
                return Err(invalid_parameter("originator", CANONICAL));
            }
            &s[..separator]
        }
    };
    string_length(hostname, "originator hostname", 1, 250)?;
    for part in hostname.split('.') {
        string_length(part, "originator part", 1, 63)?;
        if !is_label(part) {
            return Err(invalid_parameter("originator", CANONICAL));
        }
    }
    Ok(Some(hostname.to_string()))
}

/// JavaScript's `String.prototype.trim`, the reference's `trim` here
/// (`:1005`) and in `normalizeWalletHttpBaseUrl`: its white space and line
/// terminators. Rust's `char::is_whitespace` differs on two code points:
/// JavaScript trims U+FEFF, which Rust does not, and keeps U+0085, which
/// Rust trims.
pub(crate) fn trim_js(value: &str) -> &str {
    value.trim_matches(|c: char| (c.is_whitespace() && c != '\u{85}') || c == '\u{feff}')
}

/// `^\d{1,5}$` and at most 65535 (`:1017`).
fn is_port(port: &str) -> bool {
    (1..=5).contains(&port.len())
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u32>().is_ok_and(|p| p <= 65535)
}

/// `^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$` (`:1029`).
fn is_label(part: &str) -> bool {
    let bytes = part.as_bytes();
    let alnum = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    bytes.first().is_some_and(alnum)
        && bytes.last().is_some_and(alnum)
        && bytes.iter().all(|b| alnum(b) || *b == b'-')
}

/// The reference's `validateStringLength` in its words.
fn string_length(s: &str, name: &str, min: usize, max: usize) -> Result<()> {
    if s.len() < min {
        return Err(invalid_parameter(name, &format!("at least {min} length.")));
    }
    if s.len() > max {
        return Err(invalid_parameter(
            name,
            &format!("no more than {max} length."),
        ));
    }
    Ok(())
}

/// `WERR_INVALID_PARAMETER`: `The <parameter> parameter must be <mustBe>`.
fn invalid_parameter(parameter: &str, must_be: &str) -> Error {
    Error::WalletRefusal {
        class: WalletRefusalClass::InvalidParameter,
        message: format!("The {parameter} parameter must be {must_be}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(parameter: &str, must_be: &str) -> Result<Option<String>> {
        Err(invalid_parameter(parameter, must_be))
    }

    #[test]
    fn a_hostname_is_trimmed_lower_cased_and_its_port_dropped() {
        assert_eq!(validate_originator(None), Ok(None));
        for (given, normalized) in [
            ("example.com", "example.com"),
            ("  Example.COM ", "example.com"),
            ("example.com:8080", "example.com"),
            ("localhost:65535", "localhost"),
            ("a-b.c0", "a-b.c0"),
        ] {
            assert_eq!(
                validate_originator(Some(given)),
                Ok(Some(normalized.to_string())),
                "{given}"
            );
        }
    }

    /// Measured on 2026-10-27 with the reference's `validateOriginator`
    /// (`ts-stack@edf6e03`) under Node 22.18.0: U+FEFF is trimmed at either
    /// end, U+0085 is kept and refused as no hostname's.
    #[test]
    fn the_trim_is_javascripts_feff_trimmed_and_u0085_kept() {
        for given in ["\u{feff}Example.com", "example.com\u{feff}"] {
            assert_eq!(
                validate_originator(Some(given)),
                Ok(Some("example.com".to_string())),
                "{given:?}"
            );
        }
        for given in ["\u{85}Example.com", "example.com\u{85}"] {
            assert_eq!(
                validate_originator(Some(given)),
                refusal("originator", CANONICAL),
                "{given:?}"
            );
        }
    }

    #[test]
    fn a_non_canonical_originator_is_refused_in_the_references_words() {
        for given in [
            "https://example.com",
            "https://example.com/app",
            "example.com:65536",
            "example.com:123456",
            "example.com:",
            "example.com:8a",
            "a:1:2",
            "-a.com",
            "a-.com",
            "a_b.com",
            "exämple.com",
        ] {
            assert_eq!(
                validate_originator(Some(given)),
                refusal("originator", CANONICAL),
                "{given}"
            );
        }
    }

    #[test]
    fn the_three_lengths_are_refused_in_the_references_words() {
        assert_eq!(
            validate_originator(Some("  ")),
            refusal("originator", "at least 1 length.")
        );
        assert_eq!(
            validate_originator(Some(&"a".repeat(251))),
            refusal("originator", "no more than 250 length.")
        );
        assert_eq!(
            validate_originator(Some(":80")),
            refusal("originator hostname", "at least 1 length.")
        );
        assert_eq!(
            validate_originator(Some("a..b")),
            refusal("originator part", "at least 1 length.")
        );
        assert_eq!(
            validate_originator(Some(&"a".repeat(64))),
            refusal("originator part", "no more than 63 length.")
        );
    }
}
