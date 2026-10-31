//! A SHIP or SLAP advertisement read as the reference reads it (#544):
//! `decodeAdvertisement` (`ts-stack@edf6e03` `OverlayAdminTokenTemplate.ts:159-197`),
//! the static decode's checks (`:237-239`: the canonical five-field envelope,
//! the protocol, the identity key, the URI, the topic or service name, the
//! signature's length and canonical DER), and
//! `decodeAndVerifyOverlayAdvertisement` (`:199-222`: the author, the
//! signature by the identity's linked key over the four data fields and the
//! locking key that key), each refusal in the reference's words.

use super::overlay_admin_token_template::OverlayAdminTokenData;
use crate::overlay::types::Protocol;
use crate::primitives::hash::sha256;
use crate::primitives::{to_hex, PublicKey, Signature};
use crate::script::templates::pushdrop_position::{canonical_refusal, point_message};
use crate::script::templates::PushDrop;
use crate::script::LockingScript;
use crate::wallet::{Counterparty, KeyDeriver, Protocol as WalletProtocol, SecurityLevel};
use crate::{Error, Result};

/// `MAX_DISCOVERY_FIELD_BYTES` and `MAX_DISCOVERY_PAYLOAD_BYTES` (`:29-30`).
const MAX_FIELD_BYTES: usize = 4096;
const MAX_PAYLOAD_BYTES: usize = 8192;

/// `HTTPS_URI_PREFIXES` (`:35-41`).
const HTTPS_URI_PREFIXES: [&str; 5] = [
    "https://",
    "https+bsvauth://",
    "https+bsvauth+smf://",
    "https+bsvauth+scrypt-offchain://",
    "https+rtt://",
];

fn refused(words: impl Into<String>) -> Error {
    Error::OverlayError(words.into())
}

/// `toUTF8Strict`: a fatal `TextDecoder`, which drops one leading BOM.
fn strict_utf8(field: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(field)
        .map_err(|_| refused("The encoded data was not valid for encoding utf-8"))?;
    Ok(text.strip_prefix('\u{feff}').unwrap_or(text).to_string())
}

/// `decodeCanonicalPushDrop(script, { fieldCount: 5, ... })` (`:163-167`).
fn canonical(script: &LockingScript) -> Result<PushDrop> {
    let token = PushDrop::decode_before(script).map_err(|_| {
        refused(canonical_refusal(script, &[5]).unwrap_or("Script is not a valid PushDrop format"))
    })?;
    if let Some(words) = script
        .chunks()
        .first()
        .and_then(|chunk| chunk.data.as_deref())
        .and_then(point_message)
    {
        return Err(refused(words));
    }
    if token.fields.len() != 5 {
        return Err(refused("Unexpected PushDrop token field count"));
    }
    let mut payload = 0;
    for field in &token.fields {
        if field.len() > MAX_FIELD_BYTES {
            return Err(refused("PushDrop token contains an oversized field"));
        }
        payload += field.len();
        if payload > MAX_PAYLOAD_BYTES {
            return Err(refused("PushDrop token payload is too large"));
        }
    }
    if token.lock().to_binary() != script.to_binary() {
        return Err(refused(
            "PushDrop token must use the canonical PushDrop envelope",
        ));
    }
    Ok(token)
}

/// `canonicalPublicKey` (`:57-64`) on the identity key's hex.
fn identity_key(field: &[u8]) -> Result<PublicKey> {
    let text = to_hex(field);
    let name = "Discovery advertisement identity key";
    if field.len() != 33 || !matches!(field[0], 2 | 3) {
        return Err(refused(format!("{name} is invalid")));
    }
    let key = PublicKey::from_reference_der(field)
        .map_err(|_| refused(point_message(field).unwrap_or("Invalid point")))?;
    if key.to_hex() != text {
        return Err(refused(format!("{name} is not canonical")));
    }
    Ok(key)
}

/// `isAllowedPublicHostname` (`:72-76`).
fn allowed_host(url: &url::Url) -> bool {
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    host != "localhost" && host.split('.').all(|label| !label.starts_with("xn--"))
}

fn credential_free(url: &url::Url) -> bool {
    url.username().is_empty()
        && url.password().is_none_or(str::is_empty)
        && url.fragment().is_none_or(str::is_empty)
}

/// The JavaScript `trim` set: Unicode white space but U+0085, and U+FEFF.
fn js_trim(text: &str) -> &str {
    text.trim_matches(|c: char| (c.is_whitespace() && c != '\u{85}') || c == '\u{feff}')
}

/// `parsePositiveMeasurement` (`:66-70`).
fn positive_measurement(value: &str) -> bool {
    let value = js_trim(value);
    let digits = value
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(digits);
    let number_ok = regex::Regex::new(r"^\d+(?:\.\d+)?$").is_ok_and(|re| re.is_match(number));
    let unit_ok = unit.is_empty()
        || regex::Regex::new(r"^[a-zA-Z][a-zA-Z0-9/_-]*$").is_ok_and(|re| re.is_match(unit));
    number_ok
        && unit_ok
        && number
            .parse::<f64>()
            .is_ok_and(|n| n.is_finite() && n > 0.0)
}

/// `validateJs8URI` (`:107-138`).
fn js8_uri(uri: &str) -> bool {
    let Some((head, query)) = uri.split_once('?') else {
        return false;
    };
    if head != "js8c+bsvauth+smf:" {
        return false;
    }
    let names = ["lat", "long", "freq", "radius"];
    let params: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let get = |name: &str| -> Option<&str> {
        let mut found = params.iter().filter(|(k, _)| k == name);
        let first = found.next()?;
        found.next().is_none().then_some(first.1.as_str())
    };
    if params.iter().any(|(k, _)| !names.contains(&k.as_str())) {
        return false;
    }
    let (Some(lat), Some(long), Some(freq), Some(radius)) =
        (get("lat"), get("long"), get("freq"), get("radius"))
    else {
        return false;
    };
    let coordinate = |text: &str, bound: f64| {
        regex::Regex::new(r"^-?(?:0|[1-9]\d*)(?:\.\d+)?$").is_ok_and(|re| re.is_match(text))
            && text
                .parse::<f64>()
                .is_ok_and(|n| n.is_finite() && n.abs() <= bound)
    };
    coordinate(lat, 90.0)
        && coordinate(long, 180.0)
        && positive_measurement(freq)
        && positive_measurement(radius)
}

/// `canonicalAdvertisementURI` (`:140-160`), with `validateCustomHttpsURI`
/// and `validateWssURI` (`:80-105`) over the WHATWG URL.
fn advertisement_uri(value: &str) -> Result<String> {
    let invalid = || refused("Discovery advertisement URI is invalid");
    if value.is_empty() || value.len() > MAX_FIELD_BYTES || value.chars().any(char::is_control) {
        return Err(invalid());
    }
    let valid = if let Some(prefix) = HTTPS_URI_PREFIXES.iter().find(|p| value.starts_with(**p)) {
        url::Url::parse(&value.replacen(prefix, "https://", 1))
            .is_ok_and(|url| allowed_host(&url) && credential_free(&url) && url.path() == "/")
    } else if value.starts_with("wss://") {
        url::Url::parse(value)
            .is_ok_and(|url| url.scheme() == "wss" && allowed_host(&url) && credential_free(&url))
    } else {
        value.starts_with("js8c+bsvauth+smf:") && js8_uri(value)
    };
    if !valid {
        return Err(invalid());
    }
    Ok(value.to_string())
}

/// `canonicalNamePattern` (`:31-34`).
fn canonical_name(protocol: Protocol, name: &str) -> bool {
    let prefix = match protocol {
        Protocol::Ship => "tm_",
        Protocol::Slap => "ls_",
    };
    (1..=50).contains(&name.len())
        && name.strip_prefix(prefix).is_some_and(|rest| {
            rest.split('_')
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_lowercase()))
        })
}

/// `decodeAdvertisement` (`:159-197`): the advertisement and its fields.
pub(super) fn decode(script: &LockingScript) -> Result<(OverlayAdminTokenData, PushDrop)> {
    let token = canonical(script)?;
    let protocol = match strict_utf8(&token.fields[0])?.as_str() {
        "SHIP" => Protocol::Ship,
        "SLAP" => Protocol::Slap,
        _ => return Err(refused("Advertisement protocol must be SHIP or SLAP")),
    };
    let identity_key = identity_key(&token.fields[1])?;
    let domain = advertisement_uri(&strict_utf8(&token.fields[2])?)?;
    let topic_or_service = strict_utf8(&token.fields[3])?;
    if !canonical_name(protocol, &topic_or_service) {
        return Err(refused(
            "Discovery advertisement topic or service name is invalid",
        ));
    }
    let signature = &token.fields[4];
    if signature.len() < 8 || signature.len() > 80 {
        return Err(refused("Discovery advertisement signature is invalid"));
    }
    let canonical_der = crate::wallet::wire::reference_der(signature).map_err(refused)?;
    if canonical_der != *signature {
        return Err(refused(
            "Discovery advertisement signature is not canonical",
        ));
    }
    let data = OverlayAdminTokenData {
        protocol,
        identity_key,
        domain,
        topic_or_service,
    };
    Ok((data, token))
}

/// `decodeAndVerifyOverlayAdvertisement` (`:199-222`).
pub(super) fn decode_and_verify(
    script: &LockingScript,
    expected: Option<Protocol>,
) -> Result<OverlayAdminTokenData> {
    let (data, token) = decode(script)?;
    if expected.is_some_and(|expected| expected != data.protocol) {
        return Err(refused("Discovery advertisement protocol mismatch"));
    }
    let name = match data.protocol {
        Protocol::Ship => "service host interconnect",
        Protocol::Slap => "service lookup availability",
    };
    let protocol = WalletProtocol::new(SecurityLevel::Counterparty, name);
    let derived = KeyDeriver::new(None).derive_public_key(
        &protocol,
        "1",
        &Counterparty::Other(data.identity_key.clone()),
        false,
    )?;
    let signed = sha256(&token.fields[..4].concat());
    let verified = Signature::from_der(&token.fields[4])
        .is_ok_and(|signature| derived.verify(&signed, &signature));
    if !verified {
        return Err(refused("Signature is not valid"));
    }
    if derived != token.locking_public_key {
        return Err(refused(
            "Discovery advertisement locking key is not linked to its identity",
        ));
    }
    Ok(data)
}
