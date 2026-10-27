//! The two substrates' shared rules (#323): the reference's
//! `normalizeWalletHttpBaseUrl` and `toOriginHeader`
//! (`ts-stack@edf6e03` `packages/sdk/src/wallet/substrates/utils/toOriginHeader.ts`)
//! and the native client they build.

use crate::wallet::validation::trim_js;
use crate::Error;
use reqwest::{Client, Url};

/// The base URL's bound in UTF-16 units, as the reference measures it.
const MAX_BASE_URL_LENGTH: usize = 2048;

const NOT_AN_ORIGIN: &str = "Wallet HTTP baseUrl must be an exact HTTP(S) origin.";
const NOT_A_BARE_ORIGIN: &str =
    "Wallet HTTP baseUrl must be an HTTP(S) origin without credentials, path, query, or fragment.";
const CLEARTEXT: &str = "Wallet HTTP baseUrl may use cleartext HTTP only for a loopback host.";

/// The reference's `normalizeWalletHttpBaseUrl`: the base URL is an exact
/// HTTP(S) origin (no credentials, path, query or fragment; at most 2048
/// units; no surrounding whitespace), cleartext HTTP only for a loopback host
/// (`localhost`, `*.localhost`, `127.0.0.1`, `[::1]`); the answer is the
/// origin (`https://wallet.example.com:443/` is `https://wallet.example.com`).
pub(super) fn normalize_wallet_http_base_url(value: &str) -> Result<String, Error> {
    let refused = |words: &str| Error::WalletError(words.to_string());
    let length = value.encode_utf16().count();
    if !(1..=MAX_BASE_URL_LENGTH).contains(&length) || value != trim_js(value) {
        return Err(refused(NOT_AN_ORIGIN));
    }
    let parsed = Url::parse(value).map_err(|_| refused(NOT_AN_ORIGIN))?;
    let bare = matches!(parsed.scheme(), "http" | "https")
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.path() == "/"
        && parsed.query().is_none_or(str::is_empty)
        && parsed.fragment().is_none_or(str::is_empty)
        && parsed.host_str().is_some();
    if !bare {
        return Err(refused(NOT_A_BARE_ORIGIN));
    }
    let host = parsed.host_str().unwrap_or_default();
    if parsed.scheme() == "http" && !is_loopback_hostname(host) {
        return Err(refused(CLEARTEXT));
    }
    Ok(parsed.origin().ascii_serialization())
}

/// The reference's `isLoopbackHostname`.
fn is_loopback_hostname(hostname: &str) -> bool {
    let normalized = hostname.to_lowercase();
    normalized == "localhost"
        || normalized.ends_with(".localhost")
        || normalized == "127.0.0.1"
        || normalized == "[::1]"
}

/// The reference's `toOriginHeader(originator, 'http')`: a scheme-prefixed
/// originator's URL origin (its path and query trimmed), else the origin of
/// `http://<originator>`. An originator `validate_originator` accepted is a
/// hostname, so the substrate always takes the second branch.
pub(super) fn to_origin_header(originator: &str) -> Result<String, Error> {
    if has_scheme(originator) {
        if let Ok(url) = Url::parse(originator) {
            return Ok(url.origin().ascii_serialization());
        }
    }
    Url::parse(&format!("http://{originator}"))
        .map(|url| url.origin().ascii_serialization())
        .map_err(|_| Error::WalletError(format!("Invalid originator value: {originator}")))
}

/// `^[a-z][a-z0-9+.-]*:\/\/` case-insensitively.
fn has_scheme(value: &str) -> bool {
    let Some((scheme, _)) = value.split_once("://") else {
        return false;
    };
    let mut bytes = scheme.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-'))
}

/// The client `new` builds: no redirect followed, the reference's
/// `redirect: 'error'`. A client handed to `with_client` is used as given.
pub(super) fn default_client() -> Result<Client, Error> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| Error::WalletError(format!("failed to build the HTTP client: {e}")))
}

/// A redirect is refused, as the reference's `redirect: 'error'` refuses it:
/// the answer to a client that does not follow it.
pub(super) fn redirect_refused(status: reqwest::StatusCode, call: &str) -> Error {
    Error::WalletError(format!("HTTP {status} for {call}: a redirect is refused"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(words: &str) -> Result<String, Error> {
        Err(Error::WalletError(words.to_string()))
    }

    #[test]
    fn a_base_url_is_its_origin() {
        for (given, origin) in [
            ("http://localhost:3321", "http://localhost:3321"),
            ("http://localhost:3321/", "http://localhost:3321"),
            ("http://wallet.localhost", "http://wallet.localhost"),
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
            ("http://[::1]:3301", "http://[::1]:3301"),
            ("HTTP://LOCALHOST:3321", "http://localhost:3321"),
            (
                "https://wallet.example.com:443",
                "https://wallet.example.com",
            ),
            ("https://localhost:2121", "https://localhost:2121"),
            ("https://w.example?", "https://w.example"),
            ("https://w.example#", "https://w.example"),
        ] {
            assert_eq!(
                normalize_wallet_http_base_url(given),
                Ok(origin.into()),
                "{given}"
            );
        }
    }

    #[test]
    fn a_base_url_that_is_not_an_exact_origin_is_refused_in_the_references_words() {
        for given in ["", " http://localhost", "http://localhost\n", "::"] {
            assert_eq!(
                normalize_wallet_http_base_url(given),
                refused(NOT_AN_ORIGIN),
                "{given:?}"
            );
        }
        let long = format!("https://{}.example", "a".repeat(MAX_BASE_URL_LENGTH));
        assert_eq!(
            normalize_wallet_http_base_url(&long),
            refused(NOT_AN_ORIGIN)
        );
        for given in [
            "https://w.example/api",
            "https://w.example/?a=1",
            "https://w.example/#f",
            "https://user@w.example",
            "https://user:pw@w.example",
            "ftp://w.example",
            "file:///tmp",
            "localhost:3321",
        ] {
            assert_eq!(
                normalize_wallet_http_base_url(given),
                refused(NOT_A_BARE_ORIGIN),
                "{given}"
            );
        }
        for given in [
            "http://w.example",
            "http://10.0.0.1:3321",
            "http://localhost.example",
        ] {
            assert_eq!(
                normalize_wallet_http_base_url(given),
                refused(CLEARTEXT),
                "{given}"
            );
        }
    }

    /// Measured on 2026-10-27 with the reference's `HTTPWalletJSON`
    /// constructor (`ts-stack@edf6e03`) under Node 22.18.0: U+FEFF is
    /// trimmed, so the base URL is not exact; U+0085 is kept, so a trailing
    /// one is a path and a leading one or one in the host does not parse.
    #[test]
    fn a_base_url_is_trimmed_as_javascript_trims_feff_and_not_u0085() {
        for given in [
            "https://wallet.example.com/\u{feff}",
            "\u{feff}https://wallet.example.com",
            "https://wallet.example.com\u{feff}",
            "\u{85}https://wallet.example.com",
            "https://wallet.example.com\u{85}",
        ] {
            assert_eq!(
                normalize_wallet_http_base_url(given),
                refused(NOT_AN_ORIGIN),
                "{given:?}"
            );
        }
        assert_eq!(
            normalize_wallet_http_base_url("https://wallet.example.com/\u{85}"),
            refused(NOT_A_BARE_ORIGIN)
        );
    }

    #[test]
    fn an_origin_header_is_the_originators_origin() {
        assert_eq!(
            to_origin_header("example.com"),
            Ok("http://example.com".into())
        );
        assert_eq!(
            to_origin_header("http://example.com"),
            Ok("http://example.com".into())
        );
        assert_eq!(
            to_origin_header("https://example.com/app?x=1"),
            Ok("https://example.com".into())
        );
        assert_eq!(
            to_origin_header("a b"),
            Err(Error::WalletError("Invalid originator value: a b".into()))
        );
    }
}
