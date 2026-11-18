//! Every workflow file is written in one plain block style, so that a reader of its text sees
//! every key a YAML parser sees (#1034's fourth fold).
//!
//! The tests that pin the workflows (`arch_advisories_1034.rs`, `arch_ci_*`, `arch_nightly_*`)
//! read them as text, line by line. YAML lets one key be written in many ways (quoted, with a
//! space before the colon, inside a flow mapping, as an explicit `?` key, behind an anchor or a
//! merge key, after a line break a line reader does not see), and each re-read of #1034's folds
//! found a spelling its fold had not listed. So the class is closed by the style, not by a list
//! of spellings: every file under `.github/workflows/` is held here to a grammar in which a
//! mapping key can be written in exactly one way, `<indent>[- ]<name>: <value>` on a line of
//! its own, and every other form is refused by its file and line. The table of YAML's forms and
//! the rule for each is `docs/lanes/fix-1034-deny-shape.md`, "The plain style"; the differential
//! that shows the readers and this rule together miss no respelled plant is run there too.
//!
//! The grammar is `support/workflow_style.rs`'s header, and the reader of key paths built on it
//! (`key_paths`) is shared with `arch_workflow_pinned_sets_1034.rs`. Since the fifth fold the
//! style fixes the indentation too: a block two spaces past its key, so a key's whole path is
//! readable from text.
//!
//! Read at the string level; no network, no environment. Each refusal is shown on a planted
//! text.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

#[path = "support/workflow_style.rs"]
mod workflow_style;

use workflow_style::*;

fn refused(errors: &[String], needle: &str) {
    assert!(
        errors.iter().any(|e| e.contains(needle)),
        "no `{needle}` in {errors:?}"
    );
}

#[test]
fn every_workflow_is_written_in_the_plain_style_1034() {
    let (files, mut errors) = workflow_folder();
    assert!(files.len() >= 13, "{} workflows", files.len());
    for (name, text) in &files {
        errors.extend(style_errors(name, text));
    }
    assert!(
        errors.is_empty(),
        "{} breaches:\n{}",
        errors.len(),
        errors.join("\n")
    );
}

#[test]
fn each_form_that_can_hide_a_key_from_a_reader_of_lines_is_refused_1034() {
    let base = "name: x\non:\n  workflow_dispatch:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - name: s\n        run: |\n          echo a\n          defaults: inside the script\n";
    assert_eq!(style_errors("x.yml", base), Vec::<String>::new());
    for (planted, needle) in [
        (
            "    \"defaults\": {}\n",
            "line 12: a line that is no plain key",
        ),
        (
            "    'group': advisories\n",
            "line 12: a line that is no plain key",
        ),
        ("    defaults : x\n", "line 12: a line that is no plain key"),
        ("    defaults:\t x\n", "line 12: holds a character"),
        (
            "    concurrency: {group: advisories}\n",
            "line 12: a flow mapping",
        ),
        (
            "    needs: [a, {group: advisories}]\n",
            "line 12: a flow sequence with an item",
        ),
        (
            "    needs: [a: b]\n",
            "line 12: a flow sequence with an item",
        ),
        (
            "    group: >-\n      advisories\n",
            "line 12: a block scalar as the value of `group`",
        ),
        (
            "    group: |2\n      advisories\n",
            "line 12: a block scalar header other than",
        ),
        ("    group: adv\n      isories\n", "line 13: a line deeper"),
        (
            "    ? defaults\n    : x\n",
            "line 12: a line that is no plain key",
        ),
        ("    x: &x {}\n", "line 12: an anchor"),
        ("    defaults: *x\n", "line 12: an anchor or an alias"),
        (
            "    <<: {defaults: {}}\n",
            "line 12: a line that is no plain key",
        ),
        ("    defaults: !!map {}\n", "line 12: a tag"),
        ("---\njobs: {}\n", "line 12: a line that is no plain key"),
        ("%YAML 1.2\n", "line 12: a line that is no plain key"),
        ("\u{feff}\n", "line 12: holds a character"),
        ("# a\rdefaults: {}\n", "line 12: holds a character"),
        ("# a\u{85}defaults: {}\n", "line 12: holds a character"),
        ("# a\u{2028}defaults: {}\n", "line 12: holds a character"),
        (
            "    \u{a0}defaults: x\n",
            "line 12: a line that is no plain key",
        ),
        (
            "    group: \"adv\\u0069sories\"\n",
            "line 12: a quoted scalar",
        ),
        ("    group: 'adv''isories'\n", "line 12: a quoted scalar"),
        (
            "    group: \"advisories\n      \"\n",
            "line 12: a quoted scalar",
        ),
        ("    runs-on: twice\n", "line 12: the key `runs-on` twice"),
        ("    - - x\n", "line 12: a sequence inside a sequence"),
        ("    -\n", "line 12: an empty sequence item"),
        ("    defaults: a: b\n", "line 12: a plain scalar holding"),
    ] {
        let text = format!("{base}{planted}");
        refused(&style_errors("x.yml", &text), &format!("x.yml {needle}"));
    }
    // a key in a step after the block scalar's body is read as a key again
    let after = format!("{base}        shell: \"true {{0}}\"\n        shell: bash\n");
    refused(
        &style_errors("x.yml", &after),
        "x.yml line 13: the key `shell` twice",
    );
}

#[test]
fn the_re_reads_four_spellings_and_an_entry_of_another_name_are_refused_1034() {
    let docs = std::fs::read_to_string(format!(
        "{}/.github/workflows/docs.yml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("docs.yml");
    assert_eq!(style_errors("docs.yml", &docs), Vec::<String>::new());
    let concurrency = "concurrency:\n  group: docs-${{ github.event_name }}-${{ github.ref }}\n  cancel-in-progress: false\n";
    let line = docs[..docs.find(concurrency).expect("the concurrency")]
        .lines()
        .count()
        + 1;
    // the third fold's re-read, M1 to M4: each spelling of `group` passed its reader of text
    for (spelling, needle) in [
        (
            "concurrency: {\"group\": advisories, cancel-in-progress: true}\n",
            "a flow mapping",
        ),
        (
            "concurrency: {group : advisories, cancel-in-progress: true}\n",
            "a flow mapping",
        ),
        (
            "concurrency:\n  group: >-\n    advisories\n  cancel-in-progress: true\n",
            "a block scalar as the value of `group`",
        ),
        (
            "concurrency: {'group': 'release-${{ github.ref }}', cancel-in-progress: true}\n",
            "a flow mapping",
        ),
        (
            "concurrency:\n  \"group\": advisories\n",
            "a line that is no plain key",
        ),
        (
            "concurrency:\n  group : advisories\n",
            "a line that is no plain key",
        ),
    ] {
        let text = docs.replacen(concurrency, spelling, 1);
        assert_ne!(text, docs);
        let errors = style_errors("docs.yml", &text);
        assert!(
            errors.iter().any(|e| e.contains(needle)
                && (e.contains(&format!("line {line}:"))
                    || e.contains(&format!("line {}:", line + 1)))),
            "{spelling:?}: {errors:?}"
        );
    }
    for (name, is_file) in [
        ("x.YML", true),
        ("x.yml.disabled", true),
        ("x.json", true),
        ("sub", false),
        ("x.yml", false),
    ] {
        assert!(entry_error(name, is_file).is_some(), "{name}");
    }
    assert!(entry_error("x.yaml", true).is_none());
    assert!(entry_error("x.yml", true).is_none());
}

#[test]
fn a_block_indented_other_than_two_spaces_past_its_key_is_refused_1034() {
    let base = "name: x\non:\n  workflow_dispatch:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - name: s\n        run: |\n          echo a\n";
    assert_eq!(style_errors("x.yml", base), Vec::<String>::new());
    for (text, needle) in [
        // another repository's reusable workflow at indentation 6 (the fourth fold's re-read)
        (
            format!("{base}  other:\n      uses: someone/else/.github/workflows/x.yml@0\n"),
            "line 12: a block indented 4 spaces under its key at column 2",
        ),
        (
            format!("{base}  other:\n   uses: ./x.yml\n"),
            "line 12: a block indented 1 spaces under its key",
        ),
        (
            format!("{base}  other:\n    steps:\n    - run: x\n"),
            "line 13: a block indented 0 spaces under its key at column 4",
        ),
        (
            format!("{base}  other:\n    steps:\n          - run: x\n"),
            "line 13: a block indented 6 spaces",
        ),
        (
            format!("{base}  other:\n    steps:\n      -   run: x\n"),
            "line 13: more than one space after",
        ),
        (
            format!("{base}  other:\n    runs-on: x\n   needs: a\n"),
            "line 13: a line at column 3, which is no open block's column",
        ),
        (
            format!(" {base}"),
            "line 1: a line at column 1, which is no open block's column",
        ),
        (
            base.replacen("  workflow_dispatch:", "    workflow_dispatch:", 1),
            "line 3: a block indented 4 spaces",
        ),
    ] {
        refused(&style_errors("x.yml", &text), &format!("x.yml {needle}"));
    }
    // a block scalar's body takes any indentation past its key: it is text
    let body = base.replacen("          echo a\n", "              echo a\n", 1);
    assert_eq!(style_errors("x.yml", &body), Vec::<String>::new());
}

#[test]
fn the_reader_gives_every_key_path_and_its_value_1034() {
    let text = "name: x\non:\n  workflow_dispatch:\n  push:\n    branches: [main, 'beta']\njobs:\n  a:\n    concurrency:\n      group: \"Advisories\" # a comment\n    steps:\n      - name: s\n        run: |\n          echo a\n\n          echo b\n      - uses: ./x\n        with: {}\n    if: >-\n      a\n      b\n    needs: []\n";
    assert_eq!(style_errors("x.yml", text), Vec::<String>::new());
    let pairs = key_paths(text);
    let pairs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(p, v)| (p.as_str(), v.as_str()))
        .collect();
    assert_eq!(
        pairs,
        [
            ("name", "x"),
            ("on/workflow_dispatch", ""),
            ("on/push/branches/[0]", "main"),
            ("on/push/branches/[1]", "beta"),
            ("jobs/a/concurrency/group", "Advisories"),
            ("jobs/a/steps/[0]/name", "s"),
            ("jobs/a/steps/[0]/run", "echo a\n\necho b\n"),
            ("jobs/a/steps/[1]/uses", "./x"),
            ("jobs/a/steps/[1]/with", "{}"),
            ("jobs/a/if", "a b"),
            ("jobs/a/needs", "[]"),
        ]
    );
    // a quoted value is read to its closing quote, a ` #` inside it kept
    let quoted = "jobs:\n  a:\n    concurrency: 'Advisories #1' # a comment\n";
    assert_eq!(style_errors("x.yml", quoted), Vec::<String>::new());
    assert_eq!(
        key_paths(quoted),
        [("jobs/a/concurrency".to_owned(), "Advisories #1".to_owned())]
    );
    // a block at any indentation is read by its structure, as a parser reads it
    let deep = "jobs:\n  other:\n      uses: someone/else/x.yml@0\n";
    assert_eq!(
        key_paths(deep),
        [(
            "jobs/other/uses".to_owned(),
            "someone/else/x.yml@0".to_owned()
        )]
    );
}
