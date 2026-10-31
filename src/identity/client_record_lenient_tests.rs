//! The lenient reading's units (#566): what a lone surrogate becomes, the
//! names compared unit for unit, and the ill-formed texts a fuzzer would
//! find, each refused without a panic.

use super::*;

fn record(fields: &str, keyring: &str) -> String {
    format!(
        r#"{{"type":"t","serialNumber":"s","subject":"k","certifier":"c","revocationOutpoint":"o","signature":"g","fields":{{{fields}}},"keyring":{{{keyring}}}}}"#
    )
}

#[test]
fn a_lone_surrogate_is_held_as_the_replacement_character_566() {
    for (escaped, held) in [
        (r"abc\ud800", "abc\u{FFFD}"),
        (r"\uDC00abc", "\u{FFFD}abc"),
        (r"\ud800A", "\u{FFFD}A"),
        (r"\udc00\ud800", "\u{FFFD}\u{FFFD}"),
        (r"\ud800\ud800", "\u{FFFD}\u{FFFD}"),
        (r"\ud800\n", "\u{FFFD}\n"),
        (r"😀", "\u{1F600}"),
        (r"\uDBFF", "\u{FFFD}"),
    ] {
        // Unrevealed: a revealed value with a lone unit is no base64
        let text = record(&format!(r#""n":"{escaped}","m":"v""#), r#""m":"AAAA""#);
        let (object, maps) = read(&text).unwrap_or_else(|| panic!("{escaped}"));
        assert_eq!(maps.fields["n"], held, "{escaped}");
        assert_eq!(object["fields"]["n"], held, "{escaped}");
    }
}

#[test]
fn names_are_compared_unit_for_unit_before_they_are_held_566() {
    // The keyring's lone unit is not the field's: no field of that name
    let text = record(r#""n\ud800":"v""#, r#""n\ud801":"AAAA""#);
    assert!(read(&text).is_none());
    let text = record(r#""n\ud800":"v""#, r#""n\ud800":"AAAA""#);
    let (_, maps) = read(&text).unwrap_or_else(|| panic!("{text}"));
    assert_eq!(maps.keyring.keys().collect::<Vec<_>>(), ["n\u{FFFD}"]);
    // Two names one `String` would hold: skipped, never merged
    for fields in [
        r#""n\ud800":"v","n\ud801":"v""#,
        "\"n\\ud800\":\"v\",\"n\u{FFFD}\":\"v\"",
    ] {
        assert!(
            read(&record(fields, r#""n\ud800":"AAAA""#)).is_none(),
            "{fields}"
        );
    }
    // A repeated name, unit for unit, is the last value at the first place,
    // as `JSON.parse` keeps it
    let text = record(r#""n\ud800":"a","m":"b","n\ud800":"c""#, r#""m":"AAAA""#);
    let (_, maps) = read(&text).unwrap_or_else(|| panic!("{text}"));
    let fields: Vec<_> = maps.fields.iter().collect();
    assert_eq!(fields[0], (&"n\u{FFFD}".to_string(), &"c".to_string()));
    // A member named by a lone unit is a ninth member, and two such are one
    // `String`: skipped
    let text = r#"{"\ud800":1,"\ud801":2}"#;
    assert!(read(text).is_none());
}

#[test]
fn ill_formed_texts_are_refused_without_a_panic_566() {
    for text in [
        "",
        "\"",
        r#"{"a":"\ud800"#,
        r#"{"a":"\ud8"}"#,
        r#"{"a":"\ud800\u"}"#,
        r#"{"a":"\ud800\uZZZZ"}"#,
        r#"{"a":"\"#,
        r#"{"\ud800"#,
        r#"{"a":{"b":"\udc00"#,
        r#"{"a":{"b":5}}"#,
        r#"{"a":["\ud800"]}"#,
        r#"{"a":1e400}"#,
        "[]",
        "null",
    ] {
        let _ = read(text);
    }
    // An object member's values are strings, else no certificate's
    assert!(read(&record(r#""n":5"#, r#""n":"AAAA""#)).is_none());
    // A keyring value with a lone unit is no base64: skipped, as the
    // reference's decryption of it fails
    assert!(read(&record(r#""n":"v""#, r#""n":"AA\ud800A""#)).is_none());
    // So is a revealed field's value with one; an unrevealed field's is read
    assert!(read(&record(r#""n":"v\ud800","m":"w""#, r#""n":"AAAA""#)).is_none());
    assert!(read(&record(r#""n":"v","m":"w\ud800""#, r#""n":"AAAA""#)).is_some());
}

#[test]
fn held_refuses_anything_but_a_lone_surrogate_566() {
    assert_eq!(held(b"abc").as_deref(), Some("abc"));
    assert_eq!(held(&[0xed, 0xa0, 0x80]).as_deref(), Some("\u{FFFD}"));
    assert_eq!(
        held(&[0xed, 0xbf, 0xbf, b'x']).as_deref(),
        Some("\u{FFFD}x")
    );
    for bytes in [
        &[0xed][..],
        &[0xed, 0xa0],
        &[0xed, 0x9f, 0xbf, 0x80],
        &[0xff],
        &[0xc0, 0x80],
        &[0xed, 0xa0, 0x41],
    ] {
        assert_eq!(held(bytes), None, "{bytes:02x?}");
    }
}
