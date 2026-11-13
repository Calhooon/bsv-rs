//! #815: the body readers, pure.

use super::*;

/// An answer as text (`LookupAnswer` holds no `PartialEq`).
fn text(answer: Result<LookupAnswer>) -> String {
    format!("{answer:?}")
}

fn limit(name: &str) -> Result<()> {
    Err(resource_limit(name))
}

#[test]
fn the_content_type_is_the_references_base_type_815() {
    for (text, binary) in [
        ("application/octet-stream", true),
        ("Application/Octet-Stream", true),
        ("APPLICATION/OCTET-STREAM; charset=binary", true),
        ("  application/octet-stream  ;x=1", true),
        ("\tapplication/octet-stream", true),
        ("application/octet-stream;", true),
        ("text/x-octet-stream-ish", false),
        ("application/octet-streamx", false),
        ("application/json", false),
        ("octet-stream", false),
        ("application/octet-stream,application/json", false),
        ("", false),
    ] {
        assert_eq!(is_octet_stream(Some(text)), binary, "{text:?}");
    }
    assert!(!is_octet_stream(None));
    // A byte above 0x7f after the parameter separator, read as one
    // character, leaves the base type as it is
    let text = header_text(b"application/octet-stream; x=\xe9");
    assert!(is_octet_stream(Some(&text)));
}

#[test]
fn a_declared_length_past_u64_is_refused_815() {
    // 21 digits: `Number` reads a value past 2^53 - 1, not a safe integer,
    // refused; `u64`'s parser read no length (the base)
    assert_eq!(
        assert_declared_length(Some("100000000000000000000"), usize::MAX),
        limit("maxResponseBytes")
    );
    assert_eq!(
        assert_declared_length(Some("9007199254740992"), usize::MAX),
        limit("maxResponseBytes")
    );
    assert_eq!(
        assert_declared_length(Some("9007199254740991"), usize::MAX),
        Ok(())
    );
    // Leading zeros are no digits of the value
    assert_eq!(
        assert_declared_length(Some("0000000000000000000005"), 5),
        Ok(())
    );
    assert_eq!(
        assert_declared_length(Some(" 6 "), 5),
        limit("maxResponseBytes")
    );
    assert_eq!(assert_declared_length(Some("5"), 5), Ok(()));
    assert_eq!(assert_declared_length(Some("0"), 0), Ok(()));
}

#[test]
fn a_signed_length_is_no_length_815() {
    // `/^\d+$/` fails: no length, where `u64`'s parser read `+5` as 5;
    // U+0085 is no ECMAScript white space, so it stays and fails the digits
    // (U+FEFF is, and `\u{feff}5` is the length 5: the recorded cells of
    // `a_header_padded_with_one_character_is_trimmed_as_the_reference_trims_it_815`)
    for text in ["+5", "-5", "5e0", "0x5", "5 5", "", " ", "5.0", "\u{85}5"] {
        assert_eq!(assert_declared_length(Some(text), 3), Ok(()), "{text:?}");
    }
    assert_eq!(assert_declared_length(None, 0), Ok(()));
}

#[test]
fn a_json_answer_behind_a_bom_is_read_815() {
    let body = b"\xef\xbb\xbf{\"type\":\"output-list\",\"outputs\":[]}";
    assert_eq!(
        text(read_json_answer(body, 4096)),
        text(Ok(LookupAnswer::OutputList { outputs: vec![] }))
    );
    // One BOM is dropped, as `TextDecoder` drops one; a second is the
    // parse's
    let twice = b"\xef\xbb\xbf\xef\xbb\xbf{\"type\":\"output-list\",\"outputs\":[]}";
    assert!(read_json_answer(twice, 4096).is_err());
    // Bytes that are not UTF-8 refused in the reference's words
    assert_eq!(
        read_json_answer(b"{\"type\":\"\xff\"}", 4096).map(|_| ()),
        Err(Error::OverlayError(
            "Overlay response is not valid UTF-8.".into()
        ))
    );
}

fn tree_builds() -> usize {
    TREE_BUILDS.with(|n| n.get())
}

fn zeros(n: usize) -> String {
    let items = vec!["0"; n].join(",");
    format!("{{\"type\":\"output-list\",\"outputs\":[{items}]}}")
}

#[test]
fn a_long_output_list_is_refused_before_its_tree_is_built_815() {
    let before = tree_builds();
    assert_eq!(
        read_json_answer(zeros(4097).as_bytes(), 4096).map(|_| ()),
        limit("maxOutputs")
    );
    assert_eq!(
        read_json_answer(zeros(11).as_bytes(), 10).map(|_| ()),
        limit("maxOutputs")
    );
    // Past the normalizer's 4096 under a raised configured count
    assert_eq!(
        read_json_answer(zeros(4097).as_bytes(), 8192).map(|_| ()),
        normalized_output_count(4097)
    );
    assert_eq!(tree_builds(), before);
    // At the bound the tree is built (its items then refused as no item)
    assert!(read_json_answer(zeros(4096).as_bytes(), 4096).is_err());
    assert_eq!(tree_builds(), before + 1);
}

/// Bodies of every shape the #768 and #775 tests serve, and the counting
/// pass's own edges: the answer is the tree path's alone, the pass's
/// refusal included.
fn bodies() -> Vec<(String, usize)> {
    let item = r#"{"beef":[1],"outputIndex":0}"#;
    let list = |n: usize, item: &str| {
        let items = vec![item; n].join(",");
        format!(r#"{{"type":"output-list","outputs":[{items}]}}"#)
    };
    let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
    let mut bodies: Vec<String> = vec![
        // #768
        "{}".into(),
        "[]".into(),
        "\"x\"".into(),
        "null".into(),
        "5".into(),
        r#"{"type":5}"#.into(),
        r#"{"type":"output-list"}"#.into(),
        r#"{"type":"output-list","outputs":"x"}"#.into(),
        r#"{"type":"output-list","outputs":[{"beef":[1]}]}"#.into(),
        r#"{"type":"output-list","outputs":[{"beef":[1],"outputIndex":0},{"beef":"0102","outputIndex":0}]}"#.into(),
        r#"{"type":"output-list","outputs":[{"beef":[],"outputIndex":0}]}"#.into(),
        r#"{"type":"output-list","outputs":[{"beef":[1],"outputIndex":0,"context":"x"}]}"#.into(),
        r#"{"type":"output-list","outputs":[{"beef":[1],"outputIndex":0,"txid":5}]}"#.into(),
        r#"{"type":"output-list","outputs":[]}"#.into(),
        r#"{"type":"output-list","outputs":[{"beef":{"0":7},"outputIndex":0,"context":{}}]}"#.into(),
        r#"{"type":"freeform","result":null}"#.into(),
        r#"{"type":"freeform"}"#.into(),
        r#"{"type":"formula","formulas":[]}"#.into(),
        // #775's counts
        list(4096, item),
        list(4097, item),
        list(11, item),
        list(10, item),
        // A repeated key: the last kept, as `Value` keeps it
        format!(r#"{{"type":"output-list","outputs":[{}],"outputs":[]}}"#, vec!["0"; 4097].join(",")),
        format!(r#"{{"type":"output-list","outputs":[],"outputs":[{}]}}"#, vec!["0"; 4097].join(",")),
        format!(r#"{{"type":"freeform","outputs":[{}],"type":"output-list"}}"#, vec!["0"; 4097].join(",")),
        format!(r#"{{"type":"output-list","outputs":[{}],"type":"freeform","result":1}}"#, vec!["0"; 4097].join(",")),
        format!(r#"{{"type":"output-list","outputs":[{}],"type":5}}"#, vec!["0"; 4097].join(",")),
        // A body `Value` refuses after a long list: the parse's words
        format!(r#"{{"type":"output-list","outputs":[{}]"#, vec!["0"; 4097].join(",")),
        format!(r#"{{"type":"output-list","outputs":[{}]}} x"#, vec!["0"; 4097].join(",")),
        format!(r#"{{"type":"output-list","outputs":[{},{deep}]}}"#, vec!["0"; 4097].join(",")),
        format!(r#"{{"type":"output-list","outputs":[{},"\ud800"]}}"#, vec!["0"; 4097].join(",")),
        format!(r#"{{"type":"output-list","outputs":[{},1e400]}}"#, vec!["0"; 4097].join(",")),
        format!(r#"{{"type":"output-list","x":{deep},"outputs":[{}]}}"#, vec!["0"; 4097].join(",")),
        format!(r#"{{"type":"output-list","outputs":[{}],"\udfff":1}}"#, vec!["0"; 4097].join(",")),
        format!(r#"{{"type":"output-list","outputs":[{}],"y":01}}"#, vec!["0"; 4097].join(",")),
        // A long list under another type
        format!(r#"{{"type":"freeform","result":[{}]}}"#, vec!["0"; 5000].join(",")),
        format!(r#"[{}]"#, vec!["0"; 5000].join(",")),
    ];
    bodies.push(deep);
    let mut cases = vec![];
    for body in bodies {
        for max in [10, 4096, 8192] {
            cases.push((body.clone(), max));
        }
    }
    cases
}

#[test]
fn the_counting_pass_and_the_tree_path_agree_815() {
    for (body, max) in bodies() {
        let tree = tree_path(&body, max);
        let both = read_json_answer(body.as_bytes(), max);
        let shown = &body[..body.len().min(80)];
        assert_eq!(text(both), text(tree), "{shown} under {max}");
    }
}

/// One cell of `tests/vectors/lookup_header_trim_815.json`: the header text
/// the reference's `headers.get` handed over, the pad as a code point.
fn padded(cell: &serde_json::Value, body: &str) -> String {
    let pad = u32::from_str_radix(cell["pad"].as_str().unwrap_or_default(), 16)
        .ok()
        .and_then(char::from_u32)
        .unwrap_or_default();
    match cell["position"].as_str() {
        Some("after") => format!("{body}{pad}"),
        Some("before") => format!("{pad}{body}"),
        _ => format!("{body}{pad}; x=1"),
    }
}

/// #815's second fold: the content type and the declared length trimmed by
/// ECMAScript's `trim` set, as the reference trims them
/// (`LookupResolver.ts:514`, `LookupResponseReader.ts:27`), against the
/// recording of `support/lookup_header_trim_815.mjs`: 84 content types and 56
/// lengths, each padded with one character of that set, U+0085 (Rust's
/// `str::trim` takes it, ECMAScript's keeps it) or a control neither takes.
/// U+0085 is a byte a host can send (`fetch_headers` holds it), so until the
/// fold a type ending in it took the binary path here and the JSON path
/// there; a length beside it is unreachable behind hyper, pinned the same.
#[test]
fn a_header_padded_with_one_character_is_trimmed_as_the_reference_trims_it_815() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/vectors/lookup_header_trim_815.json"
    ))
    .unwrap_or_default();
    let mut differ = Vec::new();
    let types = vector["content_type"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for cell in &types {
        let text = padded(cell, "application/octet-stream");
        let binary = cell["path"] == "binary";
        if is_octet_stream(Some(&text)) != binary {
            differ.push(format!("content type {} {}", cell["pad"], cell["position"]));
        }
    }
    let lengths = vector["content_length"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for cell in &lengths {
        let text = padded(cell, "100");
        let read = cell["length"] == "read";
        if (assert_declared_length(Some(&text), 64) == limit("maxResponseBytes")) != read {
            differ.push(format!(
                "content length {} {}",
                cell["pad"], cell["position"]
            ));
        }
    }
    assert_eq!((types.len(), lengths.len()), (84, 56));
    assert!(
        differ.is_empty(),
        "cells read otherwise than the reference: {differ:?}"
    );
}
