//! The two `Debug` helpers of the secret Debug class (the second fold of PR
//! #851, 2026-11-10): a credential leaves only through a door a caller
//! names, so a header's value and a URL's user info, query and fragment are
//! never printed by `Debug`.
//!
//! [`HeaderList`] and [`HeaderMap`] print every header name and redact every
//! value, save the names in [`PUBLIC_HEADERS`] (compared ignoring ASCII
//! case), whose values are public by their protocol. A redacted value is
//! `<redacted>`, never its text or its length: a list of credential names
//! (the first fold's `authorization` alone) is right only until the name
//! nobody listed (`Cookie`, `Set-Cookie`, `X-API-Key`, a vendor's own).
//!
//! [`Url`] and [`OptionUrl`] print a URL as its scheme, host, port and path,
//! user info as `<redacted>@`, a query as `?<redacted>` and a fragment as
//! `#<redacted>`; text this reader does not take as an absolute URL with an
//! authority, or that carries a character outside printable ASCII, prints as
//! `<unparsed url>` and nothing of it. The path is printed: a credential in a
//! path segment (`/v3/<key>`) is not seen, stated in the CHANGELOG entry.
//!
//! Crate-private; `tests/secret_debug.rs` pins every type that prints
//! through them, and the unit tests below pin the readings.

use std::fmt::{Debug, Formatter, Result, Write};

/// Header names whose values are public by their protocol, compared ignoring
/// ASCII case: three of HTTP's (`content-type`, `content-length`, `accept`:
/// a media type, a byte count, a media range) and the eight names of the
/// BRC-104 transport, `auth::transports::http::headers` (`VERSION`,
/// `IDENTITY_KEY`, `NONCE`, `YOUR_NONCE`, `SIGNATURE`, `MESSAGE_TYPE`,
/// `REQUEST_ID`, `REQUESTED_CERTIFICATES`): a protocol version, a public
/// identity key, two session nonces, a signature over the message, its type,
/// a request id and a requested certificate set, each written on the wire in
/// the clear by both peers (BRC-104 `peer-to-peer/0104.md`), none a bearer
/// credential (a nonce authenticates only beside its signature). A unit test
/// under `auth` holds the eight equal to the transport's constants. Every
/// other `x-bsv-*` name is a caller's (signed and forwarded by the transport,
/// its value the caller's) and is redacted.
#[cfg_attr(not(feature = "auth"), allow(dead_code))] // used by `auth` and `storage` with `http`
pub(crate) const PUBLIC_HEADERS: &[&str] = &[
    "content-type",
    "content-length",
    "accept",
    "x-bsv-auth-version",
    "x-bsv-auth-identity-key",
    "x-bsv-auth-nonce",
    "x-bsv-auth-your-nonce",
    "x-bsv-auth-signature",
    "x-bsv-auth-message-type",
    "x-bsv-auth-request-id",
    "x-bsv-auth-requested-certificates",
];

/// Whether a header's value may be printed.
#[cfg_attr(not(feature = "auth"), allow(dead_code))] // used by `auth` and `storage` with `http`
fn is_public(name: &str) -> bool {
    PUBLIC_HEADERS.iter().any(|p| p.eq_ignore_ascii_case(name))
}

/// A header's value: its `Debug` under a public name, else `<redacted>`.
#[cfg_attr(not(feature = "auth"), allow(dead_code))] // used by `auth` and `storage` with `http`
struct Value<'a>(&'a str, &'a str);

impl Debug for Value<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        if is_public(self.0) {
            Debug::fmt(self.1, f)
        } else {
            f.write_str("<redacted>")
        }
    }
}

/// A header list as `[(name, value), ..]`, the derive's form for a `Vec`.
#[cfg_attr(not(feature = "auth"), allow(dead_code))] // used by `auth` and `storage` with `http`
pub(crate) struct HeaderList<'a>(pub(crate) &'a [(String, String)]);

impl Debug for HeaderList<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_list()
            .entries(self.0.iter().map(|(k, v)| (k, Value(k, v))))
            .finish()
    }
}

/// A header map (`IndexMap`, `HashMap`) as `{name: value, ..}`, the derive's
/// form for a map.
#[cfg_attr(not(feature = "auth"), allow(dead_code))] // used by `auth` and `storage` with `http`
pub(crate) struct HeaderMap<'a, M>(pub(crate) &'a M);

impl<M> Debug for HeaderMap<'_, M>
where
    for<'b> &'b M: IntoIterator<Item = (&'b String, &'b String)>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_map()
            .entries(self.0.into_iter().map(|(k, v)| (k, Value(k, v))))
            .finish()
    }
}

/// A URL for `Debug`, quoted as the derive quotes a `String`, or
/// `<unparsed url>`.
pub(crate) struct Url<'a>(pub(crate) &'a str);

impl Debug for Url<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match redacted_url(self.0) {
            Some(text) => {
                f.write_char('"')?;
                f.write_str(&text)?;
                f.write_char('"')
            }
            None => f.write_str("<unparsed url>"),
        }
    }
}

/// An optional URL for `Debug`: `Some(<url>)` or `None`.
pub(crate) struct OptionUrl<'a>(pub(crate) &'a Option<String>);

impl Debug for OptionUrl<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self.0 {
            Some(url) => f.debug_tuple("Some").field(&Url(url)).finish(),
            None => f.write_str("None"),
        }
    }
}

/// `scheme://[<redacted>@]host[:port][path][?<redacted>][#<redacted>]`, or
/// `None` for text that is not such a URL. Never fails, never panics.
fn redacted_url(text: &str) -> Option<String> {
    // Printable ASCII alone, and no quote or backslash (kept out of the
    // quoted form, and a backslash is a separator to a WHATWG reader).
    if !text
        .bytes()
        .all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
    {
        return None;
    }
    let (scheme, rest) = text.split_once("://")?;
    let mut chars = scheme.chars();
    if !chars.next()?.is_ascii_alphabetic()
        || !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return None;
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let (userinfo, host_port) = match authority.rfind('@') {
        Some(at) => (true, &authority[at + 1..]),
        None => (false, authority),
    };
    let (host, port) = split_host_port(host_port)?;
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '%'))
            && !(host.starts_with('[')
                && host.ends_with(']')
                && host[1..host.len() - 1]
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.')))
    {
        return None;
    }
    if !port.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
    let (path, after) = tail.split_at(path_end);
    let mut out = format!("{scheme}://");
    if userinfo {
        out.push_str("<redacted>@");
    }
    out.push_str(host);
    if !port.is_empty() || host_port.ends_with(':') {
        out.push(':');
        out.push_str(port);
    }
    out.push_str(path);
    let (query, fragment) = match after.split_once('#') {
        Some((q, _)) => (q.starts_with('?'), true),
        None => (after.starts_with('?'), false),
    };
    if query {
        out.push_str("?<redacted>");
    }
    if fragment {
        out.push_str("#<redacted>");
    }
    Some(out)
}

/// `host[:port]`, a bracketed IPv6 host kept whole.
fn split_host_port(text: &str) -> Option<(&str, &str)> {
    if text.starts_with('[') {
        let close = text.find(']')?;
        let (host, rest) = text.split_at(close + 1);
        return match rest.strip_prefix(':') {
            Some(port) => Some((host, port)),
            None if rest.is_empty() => Some((host, "")),
            None => None,
        };
    }
    Some(match text.split_once(':') {
        Some((host, port)) => (host, port),
        None => (text, ""),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> String {
        format!("{:?}", Url(text))
    }

    #[test]
    fn a_url_prints_its_scheme_host_port_and_path() {
        assert_eq!(url("https://arc.taal.com"), "\"https://arc.taal.com\"");
        assert_eq!(
            url("https://api.example.com:8443/v1/tx"),
            "\"https://api.example.com:8443/v1/tx\""
        );
        assert_eq!(url("ws://[::1]:3000/socket"), "\"ws://[::1]:3000/socket\"");
        assert_eq!(url("http://localhost:/"), "\"http://localhost:/\"");
    }

    #[test]
    fn user_info_a_query_and_a_fragment_are_redacted() {
        assert_eq!(
            url("https://user:pass@host.invalid/p?api_key=k#frag"),
            "\"https://<redacted>@host.invalid/p?<redacted>#<redacted>\""
        );
        assert_eq!(
            url("https://key@h.invalid"),
            "\"https://<redacted>@h.invalid\""
        );
        assert_eq!(
            url("https://h.invalid?x"),
            "\"https://h.invalid?<redacted>\""
        );
        assert_eq!(
            url("https://h.invalid/#x?y"),
            "\"https://h.invalid/#<redacted>\""
        );
        assert_eq!(
            url("https://h.invalid/?"),
            "\"https://h.invalid/?<redacted>\""
        );
        // An `@` in the path is not user info.
        assert_eq!(url("https://h.invalid/a@b"), "\"https://h.invalid/a@b\"");
        // User info with `@` inside it: the last `@` ends it.
        assert_eq!(
            url("https://a@b:c@h.invalid/"),
            "\"https://<redacted>@h.invalid/\""
        );
    }

    #[test]
    fn text_that_is_no_url_prints_nothing_of_itself() {
        for text in [
            "",
            "arc.taal.com",
            "user:pass@host",
            "mailto:someone@example.com",
            "https://",
            "https://host:secret/",
            "https://user:pa/ss@host/",
            "https://user:pa?ss@host/",
            "https://h.invalid/a b",
            "https://h.invalid/\u{e9}",
            "https://h.invalid/\"",
            "https://u:p\\@h.invalid/",
            "1https://h.invalid",
            "https://[::1/",
            "https://[::1]x/",
            "https://h\u{0}st/",
        ] {
            assert_eq!(url(text), "<unparsed url>", "{text:?}");
        }
    }

    #[test]
    fn an_optional_url_prints_as_the_derive_would_shape_it() {
        assert_eq!(format!("{:?}", OptionUrl(&None)), "None");
        assert_eq!(
            format!("{:?}", OptionUrl(&Some("https://u@h.invalid/".into()))),
            "Some(\"https://<redacted>@h.invalid/\")"
        );
    }

    #[test]
    fn every_header_value_is_redacted_but_the_public_names() {
        let list = vec![
            ("Cookie".to_owned(), "c=1".to_owned()),
            ("Content-Type".to_owned(), "text/plain".to_owned()),
            ("X-BSV-AUTH-NONCE".to_owned(), "bm9uY2U=".to_owned()),
            ("x-bsv-topic".to_owned(), "t".to_owned()),
        ];
        assert_eq!(
            format!("{:?}", HeaderList(&list)),
            "[(\"Cookie\", <redacted>), (\"Content-Type\", \"text/plain\"), \
             (\"X-BSV-AUTH-NONCE\", \"bm9uY2U=\"), (\"x-bsv-topic\", <redacted>)]"
        );
        let map: std::collections::HashMap<String, String> =
            [("Set-Cookie".to_owned(), "s".to_owned())].into();
        assert_eq!(
            format!("{:?}", HeaderMap(&map)),
            "{\"Set-Cookie\": <redacted>}"
        );
    }

    #[cfg(feature = "auth")]
    #[test]
    fn the_public_bsv_names_are_the_transports_constants() {
        use crate::auth::transports::http::headers;
        let constants = [
            headers::VERSION,
            headers::IDENTITY_KEY,
            headers::NONCE,
            headers::YOUR_NONCE,
            headers::SIGNATURE,
            headers::MESSAGE_TYPE,
            headers::REQUEST_ID,
            headers::REQUESTED_CERTIFICATES,
        ];
        let bsv: Vec<&str> = PUBLIC_HEADERS
            .iter()
            .copied()
            .filter(|n| n.starts_with("x-bsv-"))
            .collect();
        assert_eq!(bsv, constants);
    }

    /// The whole list, not its `x-bsv-` part alone: a name added outside the
    /// prefix (`x-vendor-auth`), removed or changed fails here.
    #[cfg(feature = "auth")]
    #[test]
    fn the_public_header_names_are_exactly_the_eleven_held() {
        use crate::auth::transports::http::headers;
        let expected = [
            "content-type",
            "content-length",
            "accept",
            headers::VERSION,
            headers::IDENTITY_KEY,
            headers::NONCE,
            headers::YOUR_NONCE,
            headers::SIGNATURE,
            headers::MESSAGE_TYPE,
            headers::REQUEST_ID,
            headers::REQUESTED_CERTIFICATES,
        ];
        assert_eq!(PUBLIC_HEADERS, expected);
    }
}
