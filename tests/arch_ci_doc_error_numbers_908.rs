//! #908, line 1: a `compile_fail` doc test's error number is read by a run.
//!
//! Stable rustdoc reads no number: a block written `compile_fail,E0639` that
//! fails for another reason (a misspelt path, a missing import, a missing
//! arm) reads `compile fail ... ok` on the required cell, which runs
//! `cargo test --doc --all-features` on stable alone. A nightly rustdoc
//! requires the number a block names among the errors it fails with (run in
//! the lane on nightly-2026-10-19: a block of `E0639` made to fail with
//! E0308 alone reads `Some expected error codes were not found: ["E0639"]`
//! there and `ok` on stable; a block that keeps its named error and gains a
//! second one passes on both). Two rules, read from the tree, no network and
//! no environment:
//!
//! - `docs.yml` carries the job [`JOB`], byte for byte: the doc suite on a
//!   dated nightly, on a dispatch alone (`RELEASING.md` step 4 dispatches
//!   `docs.yml` on the line's tip before any tag; a tag's call of the
//!   workflow skips the job, so no publish waits on a nightly compiler), its
//!   date the one `nightly.yml`'s fuzz job builds with (one dated nightly in
//!   the tree, moved in one place and read here);
//! - every `compile_fail` fence under `src/` names an error number, so the
//!   job has a number to read, or its file stands on [`UNNUMBERED`] with the
//!   count of its fences that name none and the reason. The list only
//!   shrinks: a count above what the file holds is refused as stale.
//!
//! What this does not see: a block whose number is the wrong one for the
//! property it documents but the one the compiler gives (the reader's
//! matter), and the job's run itself, which is a dispatch's.
#![allow(clippy::expect_used, clippy::panic)]

mod arch_support;

use std::collections::BTreeMap;

const DOCS_FILE: &str = ".github/workflows/docs.yml";
const NIGHTLY_FILE: &str = ".github/workflows/nightly.yml";

/// The job, from its id to the end of the file.
const JOB: &str = "  doc-error-numbers:
    name: doc error numbers
    if: github.event_name == 'workflow_dispatch'
    runs-on: ubuntu-latest
    timeout-minutes: 30
    env:
      DOC_TOOLCHAIN: nightly-2026-10-19
      RUSTFLAGS: ''
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          persist-credentials: false

      - name: Install Rust
        uses: dtolnay/rust-toolchain@e2a55d2ffb04f378e9626c28d38b36d230d1e12f # v1
        with:
          toolchain: ${{ env.DOC_TOOLCHAIN }}

      - name: Run the doc suite where rustdoc reads each block's error number
        run: cargo test --doc --all-features
";

/// Files whose `compile_fail` fences name no number, with how many and why.
const UNNUMBERED: &[(&str, usize, &str)] = &[
    (
        "src/primitives/bignum.rs",
        1,
        "the block beside it names E0277; this one's reason is stated in its prose",
    ),
    (
        "src/primitives/ec/shared_secret.rs",
        5,
        "what the type does not offer; `tests/arch_shared_secret_843d6.rs` holds the same by signature",
    ),
];

/// The value of `  NAME: value` or `      NAME: value` in a workflow's text.
fn setting<'a>(workflow: &'a str, name: &str) -> Option<&'a str> {
    workflow.lines().find_map(|line| {
        line.trim_start()
            .strip_prefix(name)?
            .strip_prefix(": ")
            .map(str::trim)
    })
}

/// What the two workflows' texts break of the job's rule.
fn job_refusals(docs: &str, nightly: &str) -> Vec<String> {
    let mut refusals = Vec::new();
    match docs.find("\n  doc-error-numbers:\n") {
        None => refusals.push(format!("{DOCS_FILE}: no job `doc-error-numbers`")),
        Some(at) => {
            let found = &docs[at + 1..];
            if found != JOB {
                let line = found
                    .lines()
                    .zip(JOB.lines())
                    .position(|(a, b)| a != b)
                    .unwrap_or_else(|| found.lines().count().min(JOB.lines().count()));
                refusals.push(format!(
                    "{DOCS_FILE}: the job `doc-error-numbers` is not the pinned text to the file's end; line {} of the job is {:?}, pinned {:?}",
                    line + 1,
                    found.lines().nth(line).unwrap_or("<the end>"),
                    JOB.lines().nth(line).unwrap_or("<the end>"),
                ));
            }
        }
    }
    let fuzz = setting(nightly, "FUZZ_TOOLCHAIN");
    let doc = setting(JOB, "DOC_TOOLCHAIN");
    if fuzz != doc {
        refusals.push(format!(
            "the doc job's nightly is {doc:?} and {NIGHTLY_FILE}'s FUZZ_TOOLCHAIN is {fuzz:?}: one dated nightly in the tree"
        ));
    }
    let dated = doc.is_some_and(|value| {
        value.strip_prefix("nightly-").is_some_and(|date| {
            date.len() == 10 && date.bytes().all(|b| b.is_ascii_digit() || b == b'-')
        })
    });
    if !dated {
        refusals.push(format!(
            "the doc job's nightly {doc:?} is not pinned by date"
        ));
    }
    refusals
}

/// Each file's count of `compile_fail` fences that name no error number.
fn unnumbered(sources: &[(String, String)]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for (path, text) in sources {
        for line in text.lines() {
            let mut rest = line;
            while let Some(at) = rest.find("```compile_fail") {
                rest = &rest[at + "```compile_fail".len()..];
                let numbered = rest.strip_prefix(",E").is_some_and(|number| {
                    number.len() >= 4 && number.bytes().take(4).all(|b| b.is_ascii_digit())
                });
                if !numbered {
                    *counts.entry(path.clone()).or_insert(0) += 1;
                }
            }
        }
    }
    counts
}

/// What the sources break of the fences' rule.
fn fence_refusals(sources: &[(String, String)]) -> Vec<String> {
    let found = unnumbered(sources);
    let mut refusals = Vec::new();
    for (path, count) in &found {
        match UNNUMBERED.iter().find(|(file, ..)| file == path) {
            None => refusals.push(format!(
                "{path}: {count} `compile_fail` fence(s) name no error number: write `compile_fail,E....`"
            )),
            Some((_, listed, _)) if count > listed => refusals.push(format!(
                "{path}: {count} `compile_fail` fences name no error number, {listed} listed: number the new one"
            )),
            Some(_) => {}
        }
    }
    for (file, listed, _) in UNNUMBERED {
        let held = found.get(*file).copied().unwrap_or(0);
        if held < *listed {
            refusals.push(format!(
                "{file}: UNNUMBERED lists {listed} and the file holds {held}: lower the entry"
            ));
        }
    }
    refusals
}

fn tree() -> Vec<(String, String)> {
    arch_support::sources()
        .into_iter()
        .map(|source| (source.path, source.text))
        .collect()
}

#[test]
fn a_dispatch_runs_the_doc_suite_on_the_dated_nightly_908() {
    let refusals = job_refusals(
        &arch_support::read(DOCS_FILE),
        &arch_support::read(NIGHTLY_FILE),
    );
    assert!(refusals.is_empty(), "{}", refusals.join("\n"));
}

#[test]
fn a_changed_doc_job_is_refused_908() {
    let docs = arch_support::read(DOCS_FILE);
    let nightly = arch_support::read(NIGHTLY_FILE);
    let plants: [(&str, &str, &str); 7] = [
        // The job would hold every publish on a nightly compiler.
        (
            "    if: github.event_name == 'workflow_dispatch'\n",
            "",
            "not the pinned text",
        ),
        // A moving nightly: a run that changes under the same commit.
        (
            "DOC_TOOLCHAIN: nightly-2026-10-19",
            "DOC_TOOLCHAIN: nightly",
            "not the pinned text",
        ),
        // Stable reads no number.
        (
            "toolchain: ${{ env.DOC_TOOLCHAIN }}",
            "toolchain: stable",
            "not the pinned text",
        ),
        // Built and never run.
        (
            "run: cargo test --doc --all-features\n",
            "run: cargo test --doc --all-features --no-run\n",
            "not the pinned text",
        ),
        // A failure absorbed.
        (
            "        run: cargo test --doc --all-features\n",
            "        run: cargo test --doc --all-features\n        continue-on-error: true\n",
            "not the pinned text",
        ),
        (
            "run: cargo test --doc --all-features\n",
            "run: cargo test --doc --all-features || true\n",
            "not the pinned text",
        ),
        ("  doc-error-numbers:\n", "  doc-numbers:\n", "no job"),
    ];
    for (from, to, message) in plants {
        assert!(docs.contains(from), "the plant's text is absent: {from:?}");
        let refusals = job_refusals(&docs.replacen(from, to, 1), &nightly);
        assert!(
            refusals.iter().any(|r| r.contains(message)),
            "{from:?} -> {to:?} passed: {refusals:?}"
        );
    }
    // The fuzz job's date moved alone.
    let moved = nightly.replacen(
        "FUZZ_TOOLCHAIN: nightly-2026-10-19",
        "FUZZ_TOOLCHAIN: nightly-2026-11-19",
        1,
    );
    assert_ne!(moved, nightly);
    assert!(job_refusals(&docs, &moved)
        .iter()
        .any(|r| r.contains("one dated nightly in the tree")));
}

#[test]
fn every_compile_fail_fence_under_src_names_its_error_number_or_is_listed_908() {
    let refusals = fence_refusals(&tree());
    assert!(refusals.is_empty(), "{}", refusals.join("\n"));
}

#[test]
fn an_unnumbered_fence_is_refused_and_a_stale_entry_too_908() {
    let numbered = (
        "src/sample.rs".to_string(),
        "/// ```compile_fail,E0639\n/// ```\n\" ```compile_fail,E0004\\n\",\n".to_string(),
    );
    assert!(fence_refusals(std::slice::from_ref(&numbered))
        .iter()
        .all(|r| r.contains("UNNUMBERED lists")));
    for fence in [
        "/// ```compile_fail\n",
        "//! ```compile_fail,should_panic\n",
        "    /// ```compile_fail,E06\n",
        "\" ```compile_fail\\n\",\n",
    ] {
        let planted = ("src/sample.rs".to_string(), fence.to_string());
        assert!(
            fence_refusals(&[planted])
                .iter()
                .any(|r| r
                    .starts_with("src/sample.rs: 1 `compile_fail` fence(s) name no error number")),
            "{fence:?} passed"
        );
    }
    // A sixth unnumbered block in a listed file, and a listed file with none.
    let mut sources = tree();
    let listed = sources
        .iter_mut()
        .find(|(path, _)| path == "src/primitives/ec/shared_secret.rs")
        .expect("the listed file");
    listed.1.push_str("/// ```compile_fail\n");
    assert!(fence_refusals(&sources)
        .iter()
        .any(|r| r.contains("6 `compile_fail` fences name no error number, 5 listed")));
    let listed = sources
        .iter_mut()
        .find(|(path, _)| path == "src/primitives/bignum.rs")
        .expect("the listed file");
    listed.1 = listed
        .1
        .replace("```compile_fail\n", "```compile_fail,E0277\n");
    assert!(fence_refusals(&sources).iter().any(|r| r
        == "src/primitives/bignum.rs: UNNUMBERED lists 1 and the file holds 0: lower the entry"));
}
