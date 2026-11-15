//! The Extended Format has one reader. Every public door that reads one
//! (an `fn from_..ef..` under `src/`, an enumerated list that only
//! shrinks) reads through `Transaction::read_ef` or through another door of
//! the list, holding no reader of its own; and the source transaction an
//! EF input is given is built in one function, `source_for` in
//! `src/transaction/transaction/ef_reader.rs`, which counts it against the
//! caller's figure before it builds it (`from_ef_bounded`,
//! `from_hex_ef_bounded`; `tests/transaction_ef_bounded.rs` pins the
//! answers). A new EF door, a second site that builds a run of default
//! outputs, a second run of outputs in the reader or a door in any spelling,
//! or the count moved after the build is a finding. Read from the
//! source, lexically (`arch_support`).
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

const READER: &str = "src/transaction/transaction/ef_reader.rs";

/// `(file, door, what it reads through)`.
const DOORS: &[(&str, &str, &str)] = &[
    (
        "src/transaction/transaction.rs",
        "from_ef",
        "Self::read_ef(ef, None)",
    ),
    (
        "src/transaction/transaction.rs",
        "from_hex_ef",
        "Self::from_ef(&bin)",
    ),
    (READER, "from_ef_bounded", "Self::read_ef(ef, Some("),
    (
        READER,
        "from_hex_ef_bounded",
        "Self::from_ef_bounded(&from_hex(hex)?",
    ),
];

/// The code of a file: doc and line comments dropped, a test file skipped.
fn code(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The body of `fn name(` in `code`, its braces matched, or `None`.
fn body<'a>(code: &'a str, name: &str) -> Option<&'a str> {
    let at = code.find(&format!("fn {name}("))?;
    let open = at + code[at..].find('{')?;
    let mut depth = 0usize;
    for (offset, c) in code[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&code[open..=open + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

fn production() -> Vec<(String, String)> {
    arch_support::sources()
        .into_iter()
        .filter(|source| !source.path.ends_with("_tests.rs"))
        .map(|source| (source.path, code(&source.text)))
        .collect()
}

/// Every `fn from_..ef..(`: a name that starts `from_` and holds `ef` as a
/// word of its own.
fn ef_doors(code: &str) -> Vec<String> {
    let mut found = Vec::new();
    for piece in code.split("fn from_").skip(1) {
        let name: String = piece
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if piece[name.len()..].starts_with('(') && name.split('_').any(|word| word == "ef") {
            found.push(format!("from_{name}"));
        }
    }
    found
}

#[test]
fn every_ef_door_is_listed_and_reads_through_the_one_reader() {
    let sources = production();
    let mut found: Vec<(String, String)> = Vec::new();
    for (path, code) in &sources {
        for door in ef_doors(code) {
            found.push((path.clone(), door));
        }
    }
    found.sort();
    let mut listed: Vec<(String, String)> = DOORS
        .iter()
        .map(|(file, door, _)| (file.to_string(), door.to_string()))
        .collect();
    listed.sort();
    assert_eq!(
        found, listed,
        "an EF door appeared or went; list it with what it reads through"
    );
    for (file, door, through) in DOORS {
        let (_, code) = sources
            .iter()
            .find(|(path, _)| path == file)
            .expect("the door's file");
        let body = body(code, door).expect("the door's body");
        assert!(
            body.contains(through),
            "{file}: `{door}` reads through `{through}`"
        );
        assert!(
            !body.contains("Reader::new"),
            "{file}: `{door}` holds a reader of its own"
        );
    }
}

#[test]
fn an_ef_inputs_source_is_built_in_one_place_after_its_count() {
    let sources = production();
    let mut sites = Vec::new();
    for (path, code) in &sources {
        for (line, text) in code.lines().enumerate() {
            let squeezed: String = text.split_whitespace().collect();
            let default_run = squeezed.contains("TransactionOutput::default();")
                || squeezed.contains("TransactionOutput::default)")
                || squeezed.contains("TransactionOutput::default())");
            if default_run && (squeezed.contains("vec![") || squeezed.contains("resize")) {
                sites.push(format!("{path}:{}", line + 1));
            }
        }
    }
    assert_eq!(
        sites.len(),
        1,
        "one site builds a run of default outputs: {sites:?}"
    );
    let (_, reader) = sources
        .iter()
        .find(|(path, _)| path == READER)
        .expect("the reader");
    let source_for = body(reader, "source_for").expect("`source_for` in the reader");
    let count = source_for
        .find("budget.as_mut()")
        .expect("the count against the figure");
    let build = source_for
        .find("vec![TransactionOutput::default();")
        .expect("the one site is `source_for`");
    assert!(count < build, "the count precedes the build");
    let callers: usize = sources
        .iter()
        .map(|(_, code)| code.matches("source_for(").count())
        .sum();
    assert_eq!(callers, 2, "`source_for` is defined once and called once");
}

/// The places in `code` that build a run of outputs in any spelling: a
/// repeat `vec![TransactionOutput::..; n]` (a `;` inside the brackets) or a
/// `resize` with an output.
fn output_runs(code: &str) -> Vec<usize> {
    let mut lines = Vec::new();
    for (line, text) in code.lines().enumerate() {
        let squeezed: String = text.split_whitespace().collect();
        let repeat = squeezed
            .match_indices("vec![TransactionOutput::")
            .any(|(at, _)| {
                let mut depth = 0i32;
                for c in squeezed[at + 5..].chars() {
                    match c {
                        '(' | '[' | '{' => depth += 1,
                        ')' | '}' => depth -= 1,
                        ']' if depth == 0 => return false,
                        ']' => depth -= 1,
                        ';' if depth == 0 => return true,
                        _ => {}
                    }
                }
                false
            });
        let resized = squeezed.contains("resize") && squeezed.contains("TransactionOutput::");
        if repeat || resized {
            lines.push(line + 1);
        }
    }
    lines
}

/// In the reader and in every listed door, the counted run of `source_for`
/// is the only run of outputs, whatever its spelling (an empty output written
/// `TransactionOutput::new(0, LockingScript::new())` builds the same run as
/// `TransactionOutput::default()`; the strength read's plant B).
#[test]
fn the_reader_and_its_doors_build_no_other_run_of_outputs_in_any_spelling() {
    let sources = production();
    let file = |name: &str| {
        sources
            .iter()
            .find(|(path, _)| path == name)
            .map(|(_, code)| code.as_str())
            .expect("a listed file")
    };
    let mut sites: Vec<String> = output_runs(file(READER))
        .into_iter()
        .map(|line| format!("{READER}:{line}"))
        .collect();
    for (path, door, _) in DOORS.iter().filter(|(path, _, _)| *path != READER) {
        let body = body(file(path), door).expect("the door's body");
        sites.extend(
            output_runs(body)
                .into_iter()
                .map(|line| format!("{path} `{door}`:{line}")),
        );
    }
    assert_eq!(
        sites.len(),
        1,
        "the reader and its doors build one run of outputs, `source_for`'s: {sites:?}"
    );
    assert!(
        body(file(READER), "source_for")
            .is_some_and(|source_for| output_runs(source_for).len() == 1),
        "the one run is in `source_for`"
    );
}
