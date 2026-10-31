//! An identity token's certificate maps in the order of its JSON text (#394):
//! the `fields` and the `keyring` the reference's `Record`s, which keep the
//! order they were written in (`ts-stack@edf6e03` `Certificate.ts:179`,
//! `VerifiableCertificate.ts:87`, `:110`), where a `serde_json::Value`
//! sorts its keys. A member that is not an object reads as empty and a value
//! that is not a string is skipped, as the `Value` reading before it did; the
//! record checks skip a token carrying either first (#553, `client_record`).

use indexmap::IndexMap;
use serde::de::IgnoredAny;
use serde::Deserialize;

/// A top-level member of the token's certificate JSON: an object kept in
/// its order, or anything else, ignored.
#[derive(Deserialize)]
#[serde(untagged)]
enum Member {
    Object(IndexMap<String, serde_json::Value>),
    Other(IgnoredAny),
}

/// The token's `fields` and `keyring`, each in the order of the text.
#[derive(Default)]
pub(super) struct TokenMaps {
    pub(super) fields: IndexMap<String, String>,
    pub(super) keyring: IndexMap<String, String>,
}

/// Reads the two maps from the certificate JSON's text; a text that does
/// not parse gives two empty maps (its caller has parsed it already).
pub(super) fn read(json: &str) -> TokenMaps {
    let Ok(mut members) = serde_json::from_str::<IndexMap<String, Member>>(json) else {
        return TokenMaps::default();
    };
    let mut strings = |name: &str| match members.swap_remove(name) {
        Some(Member::Object(entries)) => entries
            .into_iter()
            .filter_map(|(key, value)| match value {
                serde_json::Value::String(text) => Some((key, text)),
                _ => None,
            })
            .collect(),
        _ => IndexMap::new(),
    };
    TokenMaps {
        fields: strings("fields"),
        keyring: strings("keyring"),
    }
}
