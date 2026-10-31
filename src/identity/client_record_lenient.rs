//! A revelation token's certificate JSON carrying a lone UTF-16 surrogate
//! escape (#566), read as the reference's discovery reads it: `JSON.parse`
//! keeps a lone surrogate as a lone code unit (`ts-stack@edf6e03`
//! `wallet-toolbox/src/utility/identityUtils.ts:88`), where `serde_json`
//! refuses it in a `String`. `certificateRecord`'s name checks (`:100-125`)
//! compare the lone units themselves, and every byte the reference derives
//! from such a string goes through `TextEncoder` (`Certificate.ts:73-75`,
//! `:288-295`; `primitives/UTF8.ts:1-5`), which writes a lone surrogate as
//! U+FFFD. So the strings are read as `serde_json` reads a byte string, in
//! WTF-8 (a lone surrogate its own three bytes), the names compared there,
//! and each string then held with every lone surrogate as U+FFFD: the bytes
//! the reference signs, verifies and derives a key ID from.
//!
//! A keyring value, or a revealed field's value, with a lone unit is no
//! base64: the reference's decryption of it throws and skips the record
//! (`VerifiableCertificate.ts:182-191`), so it is skipped here.
//!
//! The byte-string reading of a lone surrogate before a unit that is no
//! low surrogate is `serde_json` 1.0.125's (1.0.124 refuses it), the floor
//! `Cargo.toml` names.
//!
//! Only the identity record's text comes here, and only when the strict
//! reading refuses it. Two shapes the reference reads are skipped here (the
//! #566 parity note): two names of one object differing only in their lone
//! units, or one with a lone unit beside one with U+FFFD itself, which one
//! `String` cannot tell apart; and a name whose lone unit ICU sorts before a
//! character this crate's collation places otherwise (`Certificate.ts:282`):
//! ICU 77.1 weighs a lone unit at its code point among the implicit weights,
//! before a private-use or unassigned BMP character above U+DFFF (U+E000 to
//! U+F8FF, U+FDD0, U+FFF0), where U+FFFD sorts after them here and in ICU.

use crate::identity::token_maps::TokenMaps;
use indexmap::IndexMap;
use serde::de::{Deserialize, Deserializer, Error, Visitor};
use serde_json::value::RawValue;
use serde_json::{Map, Value};
use std::fmt;

/// A JSON string's contents in WTF-8, as `serde_json` reads a byte string.
#[derive(PartialEq, Eq, Hash)]
struct Wtf8(Vec<u8>);

impl<'de> Deserialize<'de> for Wtf8 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Bytes;
        impl Visitor<'_> for Bytes {
            type Value = Wtf8;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON string")
            }
            fn visit_bytes<E: Error>(self, bytes: &[u8]) -> Result<Wtf8, E> {
                Ok(Wtf8(bytes.to_vec()))
            }
            fn visit_byte_buf<E: Error>(self, bytes: Vec<u8>) -> Result<Wtf8, E> {
                Ok(Wtf8(bytes))
            }
            fn visit_str<E: Error>(self, text: &str) -> Result<Wtf8, E> {
                Ok(Wtf8(text.as_bytes().to_vec()))
            }
        }
        deserializer.deserialize_byte_buf(Bytes)
    }
}

/// The record's members as the strict reading would hold them, a lone
/// surrogate as U+FFFD, with the two maps in the text's order; `None` skips
/// the token, as a record the reference skips (or one this crate cannot
/// hold) is skipped.
pub(super) fn read(text: &str) -> Option<(Map<String, Value>, TokenMaps)> {
    let members: IndexMap<Wtf8, &RawValue> = serde_json::from_str(text).ok()?;
    let mut object = Map::new();
    let mut maps = TokenMaps::default();
    let (mut field_names, mut keyring_names) = (Vec::new(), Vec::new());
    // The fields whose values carry a lone unit, unit for unit
    let mut lone_values = Vec::new();
    for (name, raw) in members {
        let name = held(&name.0)?;
        let json = raw.get();
        let value = match json.as_bytes().first() {
            Some(b'"') => Value::String(held(&serde_json::from_str::<Wtf8>(json).ok()?.0)?),
            Some(b'{') => {
                // An object of strings: a member that is not one is no
                // certificate's (`Certificate.ts:63-72`, `identityUtils.ts:126-129`)
                let entries: IndexMap<Wtf8, Wtf8> = serde_json::from_str(json).ok()?;
                // A keyring value with a lone unit is no base64: the
                // reference's anyone decryption of it fails and skips the
                // record (`:551-552`), whatever this crate's parsers decrypt
                if name == "keyring" && entries.values().any(|v| std::str::from_utf8(&v.0).is_err())
                {
                    return None;
                }
                let names: Vec<Wtf8> = entries.keys().map(|k| Wtf8(k.0.clone())).collect();
                if name == "fields" {
                    lone_values = entries
                        .iter()
                        .filter(|(_, v)| std::str::from_utf8(&v.0).is_err())
                        .map(|(k, _)| Wtf8(k.0.clone()))
                        .collect();
                }
                let entries = held_map(entries)?;
                let value = entries
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::String(v.clone())));
                let value = Value::Object(value.collect());
                match name.as_str() {
                    "fields" => (maps.fields, field_names) = (entries, names),
                    "keyring" => (maps.keyring, keyring_names) = (entries, names),
                    _ => {}
                }
                value
            }
            _ => serde_json::from_str(json).ok()?,
        };
        if object.insert(name, value).is_some() {
            // Two member names one `String` holds: a ninth member there
            return None;
        }
    }
    // Every keyring name a field's, unit for unit (`:122-125`): the held
    // names alone would match `\ud801` to `\ud800`; and a revealed field's
    // value with a lone unit is no base64 either, its decryption failing
    // as the keyring value's does (`VerifiableCertificate.ts:187-191`)
    keyring_names
        .iter()
        .all(|name| field_names.contains(name) && !lone_values.contains(name))
        .then_some((object, maps))
}

/// An object's entries held as `String`s, or `None` where two names become
/// one.
fn held_map(entries: IndexMap<Wtf8, Wtf8>) -> Option<IndexMap<String, String>> {
    let count = entries.len();
    let held: IndexMap<String, String> = entries
        .into_iter()
        .map(|(name, value)| Some((held(&name.0)?, held(&value.0)?)))
        .collect::<Option<_>>()?;
    (held.len() == count).then_some(held)
}

/// WTF-8 as the `String` `TextEncoder` writes it: a lone surrogate
/// (`ED A0..BF 80..BF`) as U+FFFD, any other ill-formed byte refused.
fn held(bytes: &[u8]) -> Option<String> {
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    loop {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                out.push_str(text);
                return Some(out);
            }
            Err(error) => {
                let (valid, after) = rest.split_at(error.valid_up_to());
                out.push_str(std::str::from_utf8(valid).ok()?);
                match after {
                    [0xed, 0xa0..=0xbf, 0x80..=0xbf, tail @ ..] => {
                        out.push(char::REPLACEMENT_CHARACTER);
                        rest = tail;
                    }
                    _ => return None,
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "client_record_lenient_tests.rs"]
mod tests;
