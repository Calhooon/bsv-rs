//! The checks a resolved definition passes before the client returns it.
//!
//! Two kinds, each refusing only what the reference's own registry refuses:
//!
//! - The definition's fields, as the reference's client checks a definition
//!   before it writes one and again when it reads one
//!   (`ts-stack@edf6e03` `RegistryClient.ts:36-198`, `validateDefinitionData`,
//!   called at `:309`, `:593` and `:737-776`): text lengths in UTF-8 bytes
//!   without control bytes, a URL that names a scheme naming `http` or
//!   `https` without credentials or a fragment, a canonical protocol ID, and
//!   a certificate's fields as a JSON object of descriptors.
//! - The query the lookup was asked, re-applied to each definition it
//!   answered with, as the registry's lookup services apply it
//!   (`overlays/topics/src/{basketmap,protomap,certmap}/*LookupService.ts`,
//!   `*StorageManager.ts`): the operators always, then the ID (or the name,
//!   when the query names no ID; a protocol's name first).
//!
//! Where this crate cannot judge a case exactly as the reference does, it
//! admits it: a check here never refuses a definition the reference's client
//! returns. A definition is returned as its token carries it; nothing here
//! rewrites a field.

use crate::registry::types::{
    deserialize_wallet_protocol, BasketDefinitionData, BasketQuery, CertificateDefinitionData,
    CertificateQuery, DefinitionType, ProtocolDefinitionData, ProtocolQuery,
};
use serde_json::Value;

/// `MAX_REGISTRY_TEXT_BYTES` and `MAX_REGISTRY_URL_BYTES` (`RegistryClient.ts:33-34`).
const MAX_TEXT_BYTES: usize = 4096;
const MAX_URL_BYTES: usize = 2048;

/// `registryString` (`RegistryClient.ts:58-78`): a length in UTF-8 bytes and
/// no control character but tab, line feed and carriage return.
fn text(value: &str, minimum: usize, maximum: usize) -> bool {
    let unsafe_control =
        |c: char| matches!(c, '\0'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{e}'..='\u{1f}' | '\u{7f}');
    (minimum..=maximum).contains(&value.len()) && !value.chars().any(unsafe_control)
}

/// `registryUrl` (`RegistryClient.ts:80-98`): empty, or without a scheme, as
/// given; with a scheme, `http` or `https`, no user name or password, no
/// fragment. A URL the reference's `URL` cannot parse at all is admitted
/// here (this crate carries no URL parser on this path).
fn url(value: &str) -> bool {
    if !text(value, 0, MAX_URL_BYTES) {
        return false;
    }
    let trimmed = value.trim_matches(|c: char| c.is_ascii_whitespace());
    let scheme_end = trimmed.find(':').filter(|&end| {
        let mut chars = trimmed[..end].chars();
        chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
    });
    let Some(end) = scheme_end else {
        return true;
    };
    let scheme = trimmed[..end].to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return false;
    }
    // The parser drops tabs and line breaks anywhere and C0 or space at the ends.
    let cleaned: String = value
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let cleaned = cleaned.trim_matches(|c: char| c <= ' ');
    let (before_fragment, fragment) = cleaned.split_once('#').unwrap_or((cleaned, ""));
    if !fragment.is_empty() {
        return false;
    }
    let after_scheme = before_fragment
        .split_once(':')
        .map_or("", |(_, rest)| rest)
        .trim_start_matches(['/', '\\']);
    let authority = after_scheme
        .split(['/', '\\', '?'])
        .next()
        .unwrap_or_default();
    match authority.rsplit_once('@') {
        Some((userinfo, _)) => userinfo.is_empty() || userinfo == ":",
        None => true,
    }
}

/// `isUnsafeRecordKey` (`SafeRecord.ts:2-4`).
fn unsafe_key(key: &str) -> bool {
    matches!(key, "__proto__" | "constructor" | "prototype")
}

/// `certificateFields` (`RegistryClient.ts:124-151`) over `JSON.parse`.
fn certificate_fields(json: &str) -> bool {
    let Ok(Value::Object(fields)) = serde_json::from_str::<Value>(json) else {
        return false;
    };
    let descriptor = |descriptor: &Value| {
        let Value::Object(entries) = descriptor else {
            return false;
        };
        let string = |key: &str| entries.get(key).and_then(Value::as_str);
        entries.keys().all(|key| {
            matches!(
                key.as_str(),
                "friendlyName" | "description" | "type" | "fieldIcon"
            )
        }) && matches!(string("type"), Some("text" | "imageURL" | "other"))
            && string("friendlyName").is_some_and(|v| text(v, 1, 300))
            && string("description").is_some_and(|v| text(v, 0, MAX_TEXT_BYTES))
            && string("fieldIcon").is_some_and(url)
    };
    fields.len() <= 64
        && fields
            .iter()
            .all(|(name, value)| !unsafe_key(name) && text(name, 1, 50) && descriptor(value))
}

/// `deserializeWalletProtocol` (`RegistryClient.ts:851-873`) as the
/// definition's check calls it: the name's length and control bytes.
fn protocol_id(json: &str) -> bool {
    deserialize_wallet_protocol(json).is_ok_and(|p| text(&p.protocol_name, 5, 400))
}

/// The definition's data fields (its operator last) as `validateDefinitionData`
/// admits them (`RegistryClient.ts:153-198`).
pub(crate) fn fields_admitted(definition_type: DefinitionType, fields: &[Vec<u8>]) -> bool {
    let Ok(f) = fields
        .iter()
        .map(|field| std::str::from_utf8(field))
        .collect::<std::result::Result<Vec<_>, _>>()
    else {
        return false;
    };
    let common = || text(f[1], 1, 300) && url(f[2]) && text(f[3], 0, MAX_TEXT_BYTES) && url(f[4]);
    match (definition_type, f.len()) {
        (DefinitionType::Basket, 6) => text(f[0], 1, 300) && common(),
        (DefinitionType::Protocol, 6) => protocol_id(f[0]) && common(),
        (DefinitionType::Certificate, 7) => {
            text(f[0], 1, 300) && common() && certificate_fields(f[5])
        }
        _ => false,
    }
}

/// The lookup service's `$in` over the query's operators; none asked, none
/// checked (the services refuse such a query).
fn operator_asked(asked: &Option<Vec<String>>, operator: &str) -> bool {
    asked
        .as_ref()
        .is_none_or(|list| list.is_empty() || list.iter().any(|o| o.eq_ignore_ascii_case(operator)))
}

/// `getFuzzyRegex` (`BasketMapStorageManager.ts`, `CertMapStorageManager.ts`):
/// the asked name's UTF-16 units in order, case-insensitively. Admits at
/// least what the service's expression matches.
fn fuzzy(asked: &str, name: &str) -> bool {
    let same = |a: u16, b: u16| {
        if a == b {
            return true;
        }
        let (Some(a), Some(b)) = (char::from_u32(a.into()), char::from_u32(b.into())) else {
            return false;
        };
        a.to_uppercase().eq(b.to_uppercase())
            || a.to_lowercase().eq(b.to_lowercase())
            || a.to_uppercase().eq(std::iter::once(b))
            || b.to_uppercase().eq(std::iter::once(a))
    };
    let mut units = name.encode_utf16();
    asked.encode_utf16().all(|a| units.any(|n| same(a, n)))
}

/// `BasketMapLookupService.lookup`: by ID when the query names one, else by name.
pub(crate) fn basket_answers(query: &BasketQuery, data: &BasketDefinitionData) -> bool {
    if !operator_asked(&query.registry_operators, &data.registry_operator) {
        return false;
    }
    match (&query.registry_operators, &query.basket_id, &query.name) {
        (Some(_), Some(id), _) => *id == data.basket_id,
        (Some(_), None, Some(name)) => fuzzy(name, &data.name),
        _ => true,
    }
}

/// `ProtoMapLookupService.lookup`: by name (exact) when the query names one,
/// else by protocol ID.
pub(crate) fn protocol_answers(query: &ProtocolQuery, data: &ProtocolDefinitionData) -> bool {
    if !operator_asked(&query.registry_operators, &data.registry_operator) {
        return false;
    }
    match (&query.registry_operators, &query.name, &query.protocol_id) {
        (Some(_), Some(name), _) => *name == data.name,
        (Some(_), None, Some(id)) => *id == data.protocol_id,
        _ => true,
    }
}

/// `CertMapLookupService.lookup`: by type when the query names one, else by name.
pub(crate) fn certificate_answers(
    query: &CertificateQuery,
    data: &CertificateDefinitionData,
) -> bool {
    if !operator_asked(&query.registry_operators, &data.registry_operator) {
        return false;
    }
    match (&query.registry_operators, &query.cert_type, &query.name) {
        (Some(_), Some(cert_type), _) => *cert_type == data.cert_type,
        (Some(_), None, Some(name)) => fuzzy(name, &data.name),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_is_judged_as_the_reference_client_judges_it() {
        for admitted in [
            "",
            "https://icon.example/i.png",
            "http://icon.example/i.png",
            "HTTPS://icon.example",
            "uhrp-less text",
            "//icon.example/i.png",
            "://icon.example",
            "https://@icon.example",
            "https://:@icon.example",
            "https://icon.example/#",
        ] {
            assert!(url(admitted), "{admitted:?}");
        }
        for refused in [
            "ftp://icon.example/i.png",
            "uhrp://abc",
            "data:text/plain,x",
            "https://user@icon.example",
            "https://u:p@icon.example",
            "https://icon.example/#top",
            "https://icon.example/\u{1}",
        ] {
            assert!(!url(refused), "{refused:?}");
        }
        assert!(!url(&format!("https://a.example/{}", "a".repeat(2048))));
    }

    #[test]
    fn the_fuzzy_name_matches_in_order_without_case() {
        assert!(fuzzy("pay", "Payments"));
        assert!(fuzzy("PMT", "payments"));
        assert!(!fuzzy("receipts", "Payments"));
        assert!(fuzzy("", "anything"));
        // A line break in the name is a unit like any other here.
        assert!(fuzzy("pm", "pay\nments"));
        assert!(fuzzy("ab", "a\u{2028}b"));
    }

    #[test]
    fn a_url_with_a_backslash_or_no_parse_is_judged_by_its_parts() {
        // A backslash separates as a slash does.
        assert!(url("https:\\\\@icon.example"));
        assert!(url("https://icon.example\\u@x/i.png"));
        assert!(!url("https:\\\\user@icon.example"));
        assert!(!url("https://u@icon.example\\i.png"));
        // No parse of the rest: what has no credentials and no fragment is admitted.
        assert!(url("https://["));
        assert!(url("http://icon.example:99999"));
    }

    #[test]
    fn a_certificate_fields_descriptor_description_is_bounded() {
        let fields = |description: &str| {
            serde_json::json!({ "name": {
                "friendlyName": "Name", "description": description, "type": "text", "fieldIcon": ""
            } })
            .to_string()
        };
        assert!(certificate_fields(&fields(&"d".repeat(MAX_TEXT_BYTES))));
        assert!(!certificate_fields(&fields(
            &"d".repeat(MAX_TEXT_BYTES + 1)
        )));
    }

    #[test]
    fn the_operators_and_the_id_are_checked_as_the_services_check_them() {
        assert!(operator_asked(&None, "02ab"));
        assert!(operator_asked(&Some(vec![]), "02ab"));
        assert!(operator_asked(&Some(vec!["02AB".into()]), "02ab"));
        assert!(!operator_asked(&Some(vec!["03cd".into()]), "02ab"));
        let mut data = BasketDefinitionData::new("receipts", "Receipts");
        data.registry_operator = "02ab".into();
        // An ID with no operators: no service answers such a query; nothing re-checked.
        assert!(basket_answers(
            &BasketQuery::new().with_basket_id("invoices"),
            &data
        ));
        let asked = BasketQuery::new().with_registry_operators(vec!["02ab".into()]);
        assert!(!basket_answers(
            &asked.clone().with_basket_id("invoices"),
            &data
        ));
        assert!(basket_answers(&asked.with_basket_id("receipts"), &data));
    }
}
