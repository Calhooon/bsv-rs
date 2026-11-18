//! What every workflow says for each key by which it can reach the daily alarm or the tag's
//! gate from outside their two pinned blocks is written down once, here, as a set (#1034's
//! fifth and sixth folds).
//!
//! `advisories.yml` is pinned from its `on:` line to its end and `release.yml`'s `advisories`
//! job byte for byte (`arch_advisories_1034.rs`). Another file reaches them through the platform
//! alone, and the platform's documents name how (read on 2026-11-17; the table, with the page
//! and the sentence of each row, is `docs/lanes/fix-1034-deny-shape.md`, "The keys that reach
//! the alarm from another file"):
//!
//! - a concurrency group, at a workflow's top level or a job's, is the repository's, and its
//!   name is case insensitive: a run of another workflow in the group `Advisories` cancels the
//!   daily run's pending one, or its running one under `cancel-in-progress: true`;
//! - a job that calls a reusable workflow (`jobs.<id>.uses`, of this repository or another)
//!   runs that file's jobs, with what it passes (`secrets:`);
//! - a trigger by which one workflow reacts to or is started by another (`workflow_run`,
//!   `workflow_call`, `workflow_dispatch`, `repository_dispatch`);
//! - a token's grant: `actions: write` cancels, re-runs or disables another workflow's run,
//!   `issues: write` closes or rewrites the alarm's issue; a job that states no permissions in a
//!   workflow that states none takes the repository's default, which no file shows;
//! - an expression, the one place a secret or the job's token is named (a token's power is not
//!   in the file): since the sixth fold every expression of every workflow is one set,
//!   `EXPRESSIONS`, and nothing about what an expression names is read from its spelling (the
//!   fifth fold's `TOKENS` matched three spellings, and `${{ toJSON(secrets) }}` and
//!   `${{ github['token'] }}` in a new job passed it). The jobs handed a secret are chosen by
//!   hand from that set (`SECRETS`), never by a matcher.
//!
//! These are not compared with a list of bad values (four folds each closed the comparisons the
//! read before had broken). The complete set of (file, path, value) for each key in the
//! repository today is pinned below; a value added, removed or changed anywhere fails by the
//! pin's name, and a deliberate change edits the pin in the same commit, where a reviewer reads
//! it. The paths are read by `support/workflow_style.rs`'s `key_paths`, sound on the plain style
//! (`arch_workflow_plain_style_1034.rs`), whose pairs equal a real parser's on every workflow
//! and on every respelled copy the style lets through (the lane record's differential).
//!
//! A concurrency group's name is compared as the platform compares it: its text outside
//! `${{ ... }}` folded for case, an expression kept as its text. Read at the string level; no
//! network, no environment.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

#[path = "support/workflow_style.rs"]
mod workflow_style;

use workflow_style::*;

/// One pinned row: the file, the key's path, its value.
type Row = (String, String, String);

/// A name folded as the platform folds a concurrency group's: lower case outside `${{ ... }}`,
/// each expression kept as written.
fn fold_group(value: &str) -> String {
    let mut out = String::new();
    let mut rest = value;
    while let Some(open) = rest.find("${{") {
        out.push_str(&rest[..open].to_lowercase());
        let close = rest[open..].find("}}").map_or(rest.len(), |c| open + c + 2);
        out.push_str(&rest[open..close]);
        rest = &rest[close..];
    }
    out.push_str(&rest.to_lowercase());
    out
}

fn steps(path: &str) -> Vec<&str> {
    path.split('/').collect()
}

/// The pairs under any `concurrency` key, a group's name folded.
fn groups(file: &str, pairs: &[Pair]) -> Vec<Row> {
    pairs
        .iter()
        .filter(|(p, _)| steps(p).contains(&"concurrency"))
        .map(|(p, v)| {
            let group = p.ends_with("concurrency") || p.ends_with("concurrency/group");
            let value = if group { fold_group(v) } else { v.clone() };
            (file.to_owned(), p.clone(), value)
        })
        .collect()
}

/// A job's call of a reusable workflow and what it passes: `jobs/<id>/uses`,
/// `jobs/<id>/secrets...`, `jobs/<id>/cache-mode` and any `cache-mode` (the cache the called
/// workflow may ask).
fn calls(file: &str, pairs: &[Pair]) -> Vec<Row> {
    pairs
        .iter()
        .filter(|(p, _)| {
            let s = steps(p);
            (s.len() >= 3 && s[0] == "jobs" && matches!(s[2], "uses" | "secrets"))
                || s.contains(&"cache-mode")
        })
        .map(|(p, v)| (file.to_owned(), p.clone(), v.clone()))
        .collect()
}

/// The events of a file (`on/<event>`, `on/[i]` or `on` itself, as `(file, "on", event)`), and
/// every pair but a `description` under the four by which a workflow reacts to or is started by another.
fn triggers(file: &str, pairs: &[Pair]) -> Vec<Row> {
    let mut rows = Vec::new();
    for (p, v) in pairs {
        let s = steps(p);
        if s[0] != "on" {
            continue;
        }
        let event = match s.get(1) {
            None => v.as_str(),
            Some(step) if step.starts_with('[') => v.as_str(),
            Some(step) => step,
        };
        rows.push((file.to_owned(), "on".to_owned(), event.to_owned()));
        if s.len() > 2
            && s.last() != Some(&"description")
            && matches!(
                s[1],
                "workflow_run" | "workflow_call" | "workflow_dispatch" | "repository_dispatch"
            )
        {
            rows.push((file.to_owned(), p.clone(), v.clone()));
        }
    }
    rows.sort();
    rows.dedup();
    rows
}

/// Every permission a workflow states, at its top level or a job's; and each job that states
/// none in a workflow that states none, as `(file, jobs/<id>, "the repository's default")`.
fn permissions(file: &str, pairs: &[Pair]) -> Vec<Row> {
    let mut rows: Vec<Row> = pairs
        .iter()
        .filter(|(p, _)| {
            let s = steps(p);
            s[0] == "permissions" || (s.len() >= 3 && s[0] == "jobs" && s[2] == "permissions")
        })
        .map(|(p, v)| (file.to_owned(), p.clone(), v.clone()))
        .collect();
    let top = pairs.iter().any(|(p, _)| steps(p)[0] == "permissions");
    if !top {
        let mut jobs: Vec<&str> = pairs
            .iter()
            .filter_map(|(p, _)| {
                let s = steps(p);
                (s[0] == "jobs" && s.len() >= 2).then(|| s[1])
            })
            .collect();
        jobs.dedup();
        for job in jobs {
            let stated = pairs.iter().any(|(p, _)| {
                let s = steps(p);
                s.len() >= 3 && s[0] == "jobs" && s[1] == job && s[2] == "permissions"
            });
            if !stated {
                rows.push((
                    file.to_owned(),
                    format!("jobs/{job}"),
                    "the repository's default".to_owned(),
                ));
            }
        }
    }
    rows
}

/// The end of the expression opening at `open` (`${{`) in `value`: just past the earliest `}}`
/// outside a single-quoted string (the expression language's one string form, `''` inside it a
/// quote, which toggling on each `'` reads), or the value's end when none closes it.
fn expression_end(value: &str, open: usize) -> usize {
    let bytes = value.as_bytes();
    let mut in_string = false;
    let mut j = open + 3;
    while j < bytes.len() {
        if bytes[j] == b'\'' {
            in_string = !in_string;
        } else if !in_string && bytes[j] == b'}' && bytes.get(j + 1) == Some(&b'}') {
            return j + 2;
        }
        j += 1;
    }
    bytes.len()
}

/// Every expression of a workflow, as `(file, path, text as written)`: the whole value of every
/// key named `if` (the conditional keys, `jobs/<id>/if` and `jobs/<id>/steps/[i]/if`, take an
/// expression with or without `${{ }}`; a key of that name elsewhere is pinned whole too), and
/// every `${{ ... }}` of every other value, a block scalar's body read as the parser reads it
/// (folded lines joined). Nothing about what an expression names is read: the set is compared
/// whole with [`EXPRESSIONS`] (#1034's sixth fold).
fn expressions(file: &str, pairs: &[Pair]) -> Vec<Row> {
    let mut rows = Vec::new();
    for (p, v) in pairs {
        if p == "if" || p.ends_with("/if") {
            rows.push((file.to_owned(), p.clone(), v.clone()));
            continue;
        }
        let mut at = 0;
        while let Some(found) = v[at..].find("${{") {
            let open = at + found;
            let close = expression_end(v, open);
            rows.push((file.to_owned(), p.clone(), v[open..close].to_owned()));
            at = close;
        }
    }
    rows
}

/// FNV-1a over a job's pairs, each path and value followed by a zero byte.
fn digest(pairs: &[&Pair]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for (p, v) in pairs {
        for byte in p.bytes().chain([0]).chain(v.bytes()).chain([0]) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!("{hash:016x}")
}

/// Each job that holds a power the file does not bound (a grant of `actions: write`,
/// `issues: write` or `write-all`, its own or its workflow's when it states none; or a row of
/// [`SECRETS`], the hand-chosen expressions that hand it a secret, whose scope no file shows),
/// pinned whole by a digest of its pairs:
/// `(file, jobs/<id>, digest)`. Any line of such a job changed (a step that runs
/// `gh run cancel` or closes an issue, where the grant already stands) moves its digest.
fn holders(file: &str, pairs: &[Pair]) -> Vec<Row> {
    let grants = |prefix: &str| {
        pairs.iter().any(|(p, v)| {
            p.strip_prefix(prefix).is_some_and(|rest| {
                (rest.is_empty() && v == "write-all")
                    || (matches!(rest, "/actions" | "/issues") && v == "write")
            })
        })
    };
    let top = grants("permissions");
    let mut jobs: Vec<&str> = pairs
        .iter()
        .filter_map(|(p, _)| {
            let s = steps(p);
            (s[0] == "jobs" && s.len() >= 2).then(|| s[1])
        })
        .collect();
    jobs.dedup();
    let mut rows = Vec::new();
    for job in jobs {
        let prefix = format!("jobs/{job}/");
        let own: Vec<&Pair> = pairs
            .iter()
            .filter(|(p, _)| p.starts_with(&prefix))
            .collect();
        let states = own
            .iter()
            .any(|(p, _)| p.starts_with(&format!("{prefix}permissions")));
        let granted = grants(&format!("{prefix}permissions")) || (top && !states);
        let secret = SECRETS
            .iter()
            .any(|(f, p, _)| *f == file && p.starts_with(&prefix));
        if granted || secret {
            rows.push((file.to_owned(), format!("jobs/{job}"), digest(&own)));
        }
    }
    rows
}

/// The six pinned sets, by name, each its reader and its rows.
type Reader = fn(&str, &[Pair]) -> Vec<Row>;
const SETS: [(&str, Reader); 6] = [
    ("GROUPS", groups),
    ("CALLS", calls),
    ("TRIGGERS", triggers),
    ("PERMISSIONS", permissions),
    ("EXPRESSIONS", expressions),
    ("HOLDERS", holders),
];

fn pinned(name: &str) -> &'static [(&'static str, &'static str, &'static str)] {
    match name {
        "GROUPS" => &GROUPS,
        "CALLS" => &CALLS,
        "TRIGGERS" => &TRIGGERS,
        "PERMISSIONS" => &PERMISSIONS,
        "EXPRESSIONS" => &EXPRESSIONS,
        "HOLDERS" => &HOLDERS,
        _ => panic!("{name}"),
    }
}

/// Where the workflows' rows of each set differ from its pin: each row added or removed,
/// named by the pin.
fn set_errors(files: &[(String, String)]) -> Vec<String> {
    let read: Vec<(String, Vec<Pair>)> = files
        .iter()
        .map(|(file, text)| (file.clone(), key_paths(text)))
        .collect();
    set_errors_of(&read)
}

/// [`set_errors`] on each file's pairs, however they were read (the differential hands it a
/// real parser's).
fn set_errors_of(files: &[(String, Vec<Pair>)]) -> Vec<String> {
    let mut errors = Vec::new();
    for (name, reader) in SETS {
        let mut found: Vec<Row> = files
            .iter()
            .flat_map(|(file, pairs)| reader(file, pairs))
            .collect();
        found.sort();
        let mut expected: Vec<Row> = pinned(name)
            .iter()
            .map(|(a, b, c)| ((*a).to_owned(), (*b).to_owned(), (*c).to_owned()))
            .collect();
        expected.sort();
        let mut rest = expected.clone();
        for row in &found {
            if let Some(at) = rest.iter().position(|r| r == row) {
                rest.remove(at);
            } else {
                errors.push(format!(
                    "{name}: a row the workflows hold and the pin does not: {row:?} (a change of a key that can reach the alarm or the tag's gate; a deliberate one edits {name} in the same commit, #1034)"
                ));
            }
        }
        for row in rest {
            errors.push(format!(
                "{name}: a row the pin holds and the workflows do not: {row:?} (#1034)"
            ));
        }
    }
    errors
}

fn files() -> Vec<(String, String)> {
    let (files, errors) = workflow_folder();
    assert!(errors.is_empty(), "{errors:?}");
    assert!(files.len() >= 13, "{} workflows", files.len());
    files
}

/// A copy of the workflows with `file`'s text replaced through `edit`.
fn planted(
    files: &[(String, String)],
    file: &str,
    edit: impl Fn(&str) -> String,
) -> Vec<(String, String)> {
    let mut copy = files.to_vec();
    let text = &mut copy.iter_mut().find(|(n, _)| n == file).expect(file).1;
    let changed = edit(text);
    assert_ne!(&changed, text, "{file}: the plant changed nothing");
    *text = changed;
    copy
}

fn refused_by(errors: &[String], pin: &str) {
    assert!(
        errors.iter().any(|e| e.starts_with(&format!("{pin}: "))),
        "not refused by {pin}: {errors:?}"
    );
}

#[test]
fn every_set_equals_its_pin_on_the_tree_1034() {
    let files = files();
    for (name, text) in &files {
        assert_eq!(style_errors(name, text), Vec::<String>::new());
        assert!(
            !key_paths(text).iter().any(|(p, _)| p == "<unread>"),
            "{name}"
        );
    }
    let errors = set_errors(&files);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn a_group_name_is_folded_for_case_and_an_expression_kept_1034() {
    assert_eq!(fold_group("Advisories"), "advisories");
    assert_eq!(
        fold_group("Release-${{ github.REF }}-X"),
        "release-${{ github.REF }}-x"
    );
    assert_eq!(fold_group("${{ 'Advisories' }}"), "${{ 'Advisories' }}");
}

#[test]
fn the_re_reads_two_plants_are_refused_by_their_pins_1034() {
    let files = files();
    // a group in another case, in a job of msrv.yml and at its top level
    let job = planted(&files, "msrv.yml", |t| {
        t.replacen(
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    concurrency: Advisories\n",
            1,
        )
    });
    refused_by(&set_errors(&job), "GROUPS");
    let top = planted(&files, "msrv.yml", |t| {
        t.replacen("  group: msrv-", "  group: Release-x-msrv-", 1)
    });
    refused_by(&set_errors(&top), "GROUPS");
    // another repository's reusable workflow at indentation 6, which the plain style before
    // the fifth fold let through
    let call = planted(&files, "docs.yml", |t| {
        format!("{t}  other:\n      uses: someone/else/.github/workflows/x.yml@0123456789012345678901234567890123456789\n")
    });
    refused_by(&set_errors(&call), "CALLS");
    assert!(style_errors(
        "docs.yml",
        &call.iter().find(|(n, _)| n == "docs.yml").expect("docs").1
    )
    .iter()
    .any(|e| e.contains("a block indented 4 spaces under its key")));
}

#[test]
fn each_kind_of_change_is_refused_by_its_pin_in_any_file_and_at_any_level_1034() {
    let files = files();
    // a group written in another case, in every file, at the top level and in a job
    for (name, text) in &files {
        if text.contains("\nconcurrency:\n  group: ") {
            let copy = planted(&files, name, |t| {
                let at = t.find("\nconcurrency:\n  group: ").expect("group") + 23;
                let mut s = t.to_owned();
                let c = s[at..].chars().next().expect("a name");
                s.replace_range(at..at + c.len_utf8(), &c.to_uppercase().to_string());
                s
            });
            // an upper-cased leading letter is the same group to the platform: not a change
            assert!(
                set_errors(&copy).is_empty(),
                "{name}: {:?}",
                set_errors(&copy)
            );
            let copy = planted(&files, name, |t| {
                t.replacen("\nconcurrency:\n  group: ", "\nconcurrency:\n  group: X", 1)
            });
            refused_by(&set_errors(&copy), "GROUPS");
        }
        // the end of the opening job's key line (`  <id>:`), past any comment
        let jobs_at = text.find("\njobs:\n").expect("jobs") + 7;
        let mut first_job_end = jobs_at;
        for line in text[jobs_at..].split_inclusive('\n') {
            if plain_key(line.strip_prefix("  ").unwrap_or("#")).is_some() {
                first_job_end += line.len() - 1;
                break;
            }
            first_job_end += line.len();
        }
        for plant in [
            "    concurrency: ADVISORIES",
            "    concurrency:\n      group: Release-${{ github.ref }}",
            "    uses: ./.github/workflows/advisories.yml",
            "    uses: someone/else/.github/workflows/x.yml@0123456789012345678901234567890123456789",
            "    permissions:\n      actions: write",
            "    permissions:\n      issues: write",
            "    env:\n      T: ${{ secrets.ANY }}",
        ] {
            let copy = planted(&files, name, |t| {
                format!("{}\n{plant}{}", &t[..first_job_end], &t[first_job_end..])
            });
            assert_eq!(
                style_errors(name, &copy.iter().find(|(n, _)| n == name).expect(name).1)
                    .iter()
                    .filter(|e| !e.contains("twice in one mapping"))
                    .count(),
                0,
                "{name}: {plant}"
            );
            let pin = if plant.contains("concurrency") {
                "GROUPS"
            } else if plant.contains("uses") {
                "CALLS"
            } else if plant.contains("permissions") {
                "PERMISSIONS"
            } else {
                "EXPRESSIONS"
            };
            refused_by(&set_errors(&copy), pin);
        }
    }
    // a second declaration at another level, a moved level
    let copy = planted(&files, "docs.yml", |t| {
        t.replacen("\njobs:\n", "\nconcurrency2: x\njobs:\n", 1)
    });
    assert!(set_errors(&copy).is_empty(), "a key that is no concurrency");
    // a new trigger of each kind, in each file
    let mut planted_triggers = 0;
    for (name, text) in &files {
        for event in [
            "  workflow_run:\n    workflows: [ci]\n    types: [completed]",
            "  workflow_call:",
            "  repository_dispatch:",
            "  workflow_dispatch:\n    inputs:\n      x:\n        type: string",
        ] {
            let key = event.lines().next().expect("a key");
            if text.contains(&format!("\n{key}")) {
                continue;
            }
            let copy = planted(&files, name, |t| {
                t.replacen("\non:\n", &format!("\non:\n{event}\n"), 1)
            });
            refused_by(&set_errors(&copy), "TRIGGERS");
            planted_triggers += 1;
        }
    }
    assert!(planted_triggers >= 30, "{planted_triggers}");
    // a job that states no permissions in a workflow that states none
    let copy = planted(&files, "docs.yml", |t| {
        t.replacen("permissions:\n  contents: read\n", "", 1)
    });
    let errors = set_errors(&copy);
    refused_by(&errors, "PERMISSIONS");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("the repository's default")),
        "{errors:?}"
    );
}

/// The groups of every workflow: `(file, path, value)`, a group's name folded for case.
const GROUPS: [(&str, &str, &str); 24] = [
    ("advisories.yml", "concurrency/cancel-in-progress", "false"),
    ("advisories.yml", "concurrency/group", "advisories"),
    ("bench.yml", "concurrency/cancel-in-progress", "false"),
    ("bench.yml", "concurrency/group", "bench-${{ github.event_name }}-${{ inputs.bench_baseline_record && 'record-' || '' }}${{ github.ref }}"),
    ("ci.yml", "concurrency/cancel-in-progress", "${{ !startsWith(github.ref, 'refs/tags/') }}"),
    ("ci.yml", "concurrency/group", "ci-${{ github.event_name }}-${{ github.ref }}"),
    ("docs.yml", "concurrency/cancel-in-progress", "false"),
    ("docs.yml", "concurrency/group", "docs-${{ github.event_name }}-${{ github.ref }}"),
    ("features.yml", "concurrency/cancel-in-progress", "false"),
    ("features.yml", "concurrency/group", "features-${{ github.event_name }}-${{ github.ref }}"),
    ("machete.yml", "concurrency/cancel-in-progress", "false"),
    ("machete.yml", "concurrency/group", "machete-${{ github.event_name }}-${{ github.ref }}"),
    ("msrv.yml", "concurrency/cancel-in-progress", "false"),
    ("msrv.yml", "concurrency/group", "msrv-${{ github.event_name }}-${{ github.ref }}"),
    ("nightly.yml", "concurrency/cancel-in-progress", "false"),
    ("nightly.yml", "concurrency/group", "nightly-${{ github.ref }}"),
    ("release.yml", "concurrency/cancel-in-progress", "false"),
    ("release.yml", "concurrency/group", "release-${{ github.ref }}"),
    ("sibling-judge.yml", "concurrency/cancel-in-progress", "false"),
    ("sibling-judge.yml", "concurrency/group", "sibling-judge-${{ github.event.workflow_run.head_sha || inputs.run_id }}"),
    ("sibling-run.yml", "concurrency/cancel-in-progress", "true"),
    ("sibling-run.yml", "concurrency/group", "sibling-run-${{ github.event_name }}-${{ github.ref }}"),
    ("sync-main-into-beta.yml", "concurrency/cancel-in-progress", "false"),
    ("sync-main-into-beta.yml", "concurrency/group", "sync-main-into-beta"),
];
/// Every job's call of a reusable workflow, what it passes, and every `cache-mode`.
const CALLS: [(&str, &str, &str); 8] = [
    (
        "release.yml",
        "jobs/bench/secrets/BSV_SCRIPT_CORPUS_TOKEN",
        "${{ secrets.BSV_SCRIPT_CORPUS_TOKEN }}",
    ),
    (
        "release.yml",
        "jobs/bench/uses",
        "./.github/workflows/bench.yml",
    ),
    (
        "release.yml",
        "jobs/ci/secrets/DEPENDENTS_READ_TOKEN",
        "${{ secrets.DEPENDENTS_READ_TOKEN }}",
    ),
    ("release.yml", "jobs/ci/uses", "./.github/workflows/ci.yml"),
    (
        "release.yml",
        "jobs/docs/uses",
        "./.github/workflows/docs.yml",
    ),
    (
        "release.yml",
        "jobs/features/uses",
        "./.github/workflows/features.yml",
    ),
    (
        "release.yml",
        "jobs/machete/uses",
        "./.github/workflows/machete.yml",
    ),
    (
        "release.yml",
        "jobs/msrv/uses",
        "./.github/workflows/msrv.yml",
    ),
];
/// Every file's events, and every pair under `workflow_run`, `workflow_call`,
/// `workflow_dispatch` and `repository_dispatch`.
const TRIGGERS: [(&str, &str, &str); 45] = [
    ("advisories.yml", "on", "schedule"),
    ("advisories.yml", "on", "workflow_dispatch"),
    ("bench.yml", "on", "workflow_call"),
    ("bench.yml", "on", "workflow_dispatch"),
    (
        "bench.yml",
        "on/workflow_call/secrets/BSV_SCRIPT_CORPUS_TOKEN/required",
        "false",
    ),
    (
        "bench.yml",
        "on/workflow_dispatch/inputs/bench_baseline_record/default",
        "false",
    ),
    (
        "bench.yml",
        "on/workflow_dispatch/inputs/bench_baseline_record/type",
        "boolean",
    ),
    ("ci.yml", "on", "pull_request"),
    ("ci.yml", "on", "push"),
    ("ci.yml", "on", "workflow_call"),
    ("ci.yml", "on", "workflow_dispatch"),
    (
        "ci.yml",
        "on/workflow_call/secrets/DEPENDENTS_READ_TOKEN/required",
        "false",
    ),
    ("docs.yml", "on", "workflow_call"),
    ("docs.yml", "on", "workflow_dispatch"),
    ("features.yml", "on", "workflow_call"),
    ("features.yml", "on", "workflow_dispatch"),
    ("front-pages.yml", "on", "workflow_dispatch"),
    (
        "front-pages.yml",
        "on/workflow_dispatch/inputs/wait/default",
        "0",
    ),
    (
        "front-pages.yml",
        "on/workflow_dispatch/inputs/wait/required",
        "false",
    ),
    ("machete.yml", "on", "workflow_call"),
    ("machete.yml", "on", "workflow_dispatch"),
    ("msrv.yml", "on", "workflow_call"),
    ("msrv.yml", "on", "workflow_dispatch"),
    ("nightly.yml", "on", "workflow_dispatch"),
    (
        "nightly.yml",
        "on/workflow_dispatch/inputs/commit/default",
        "",
    ),
    (
        "nightly.yml",
        "on/workflow_dispatch/inputs/commit/required",
        "false",
    ),
    (
        "nightly.yml",
        "on/workflow_dispatch/inputs/heavy_max_parallel/default",
        "",
    ),
    (
        "nightly.yml",
        "on/workflow_dispatch/inputs/heavy_max_parallel/required",
        "false",
    ),
    (
        "nightly.yml",
        "on/workflow_dispatch/inputs/mode/default",
        "incremental",
    ),
    (
        "nightly.yml",
        "on/workflow_dispatch/inputs/mode/options/[0]",
        "incremental",
    ),
    (
        "nightly.yml",
        "on/workflow_dispatch/inputs/mode/options/[1]",
        "complete",
    ),
    (
        "nightly.yml",
        "on/workflow_dispatch/inputs/mode/type",
        "choice",
    ),
    (
        "nightly.yml",
        "on/workflow_dispatch/inputs/weekly/default",
        "false",
    ),
    (
        "nightly.yml",
        "on/workflow_dispatch/inputs/weekly/type",
        "boolean",
    ),
    ("release.yml", "on", "push"),
    ("sibling-judge.yml", "on", "workflow_dispatch"),
    ("sibling-judge.yml", "on", "workflow_run"),
    (
        "sibling-judge.yml",
        "on/workflow_dispatch/inputs/run_id/required",
        "true",
    ),
    (
        "sibling-judge.yml",
        "on/workflow_dispatch/inputs/run_id/type",
        "string",
    ),
    (
        "sibling-judge.yml",
        "on/workflow_run/types/[0]",
        "completed",
    ),
    (
        "sibling-judge.yml",
        "on/workflow_run/workflows/[0]",
        "sibling-run",
    ),
    ("sibling-run.yml", "on", "pull_request"),
    ("sibling-run.yml", "on", "workflow_dispatch"),
    ("sync-main-into-beta.yml", "on", "push"),
    ("sync-main-into-beta.yml", "on", "workflow_dispatch"),
];
/// Every permission stated, and each job that takes the repository's default (none).
const PERMISSIONS: [(&str, &str, &str); 54] = [
    ("advisories.yml", "permissions/contents", "read"),
    ("advisories.yml", "permissions/issues", "write"),
    ("bench.yml", "permissions/contents", "read"),
    ("ci.yml", "jobs/semver/permissions/contents", "read"),
    ("ci.yml", "jobs/semver/permissions/pull-requests", "read"),
    ("ci.yml", "jobs/test/permissions/contents", "read"),
    ("ci.yml", "jobs/test/permissions/pull-requests", "read"),
    ("ci.yml", "permissions/contents", "read"),
    ("docs.yml", "permissions/contents", "read"),
    ("features.yml", "permissions/contents", "read"),
    ("front-pages.yml", "permissions/contents", "read"),
    ("machete.yml", "permissions/contents", "read"),
    ("msrv.yml", "permissions/contents", "read"),
    ("nightly.yml", "jobs/bench/permissions/actions", "write"),
    (
        "nightly.yml",
        "jobs/ci-full-beta/permissions/actions",
        "write",
    ),
    (
        "nightly.yml",
        "jobs/ci-full-main/permissions/actions",
        "write",
    ),
    ("nightly.yml", "jobs/fuzz/permissions/contents", "read"),
    ("nightly.yml", "jobs/fuzz/permissions/issues", "write"),
    (
        "nightly.yml",
        "jobs/mutants-tail/permissions/contents",
        "read",
    ),
    ("nightly.yml", "jobs/mutants/permissions/contents", "read"),
    (
        "nightly.yml",
        "jobs/mutation-score/permissions/contents",
        "read",
    ),
    ("nightly.yml", "jobs/source/permissions/actions", "read"),
    ("nightly.yml", "jobs/source/permissions/contents", "read"),
    ("nightly.yml", "permissions", "{}"),
    (
        "release.yml",
        "jobs/advisories/permissions/contents",
        "read",
    ),
    ("release.yml", "jobs/bench/permissions/contents", "read"),
    ("release.yml", "jobs/ci/permissions/contents", "read"),
    ("release.yml", "jobs/ci/permissions/pull-requests", "read"),
    ("release.yml", "jobs/docs/permissions/contents", "read"),
    ("release.yml", "jobs/features/permissions/contents", "read"),
    (
        "release.yml",
        "jobs/front-pages/permissions/contents",
        "read",
    ),
    ("release.yml", "jobs/machete/permissions/contents", "read"),
    ("release.yml", "jobs/msrv/permissions/contents", "read"),
    ("release.yml", "jobs/page/permissions/actions", "read"),
    ("release.yml", "jobs/page/permissions/checks", "read"),
    ("release.yml", "jobs/page/permissions/contents", "write"),
    ("release.yml", "jobs/publish/permissions/contents", "read"),
    ("release.yml", "jobs/publish/permissions/id-token", "write"),
    ("release.yml", "jobs/version/permissions/actions", "read"),
    ("release.yml", "jobs/version/permissions/contents", "read"),
    ("release.yml", "permissions/contents", "read"),
    (
        "sibling-judge.yml",
        "jobs/judge/permissions/actions",
        "read",
    ),
    (
        "sibling-judge.yml",
        "jobs/judge/permissions/contents",
        "read",
    ),
    (
        "sibling-judge.yml",
        "jobs/judge/permissions/pull-requests",
        "read",
    ),
    (
        "sibling-judge.yml",
        "jobs/report/permissions/actions",
        "read",
    ),
    (
        "sibling-judge.yml",
        "jobs/report/permissions/contents",
        "read",
    ),
    (
        "sibling-judge.yml",
        "jobs/report/permissions/pull-requests",
        "read",
    ),
    ("sibling-judge.yml", "permissions/contents", "read"),
    ("sibling-run.yml", "permissions/contents", "read"),
    (
        "sync-main-into-beta.yml",
        "jobs/sync/permissions/actions",
        "write",
    ),
    (
        "sync-main-into-beta.yml",
        "jobs/sync/permissions/contents",
        "write",
    ),
    (
        "sync-main-into-beta.yml",
        "jobs/sync/permissions/issues",
        "write",
    ),
    (
        "sync-main-into-beta.yml",
        "jobs/sync/permissions/pull-requests",
        "write",
    ),
    ("sync-main-into-beta.yml", "permissions/contents", "read"),
];
/// Every expression of every workflow: `(file, path, text as written)`, the whole value of each
/// `if` and each `${{ ... }}` of every other value (#1034's sixth fold). An expression added,
/// removed or changed anywhere fails by this pin's name, whatever it says; a deliberate change
/// edits this list in the same commit.
static EXPRESSIONS: [(&str, &str, &str); 347] = [
    ("advisories.yml", "jobs/advisories/name", "${{ matrix.line }}"),
    ("advisories.yml", "jobs/advisories/steps/[0]/with/ref", "${{ matrix.line }}"),
    ("advisories.yml", "jobs/advisories/steps/[5]/env/GH_TOKEN", "${{ github.token }}"),
    ("advisories.yml", "jobs/advisories/steps/[5]/env/LINE", "${{ matrix.line }}"),
    ("bench.yml", "concurrency/group", "${{ github.event_name }}"),
    ("bench.yml", "concurrency/group", "${{ github.ref }}"),
    ("bench.yml", "concurrency/group", "${{ inputs.bench_baseline_record && 'record-' || '' }}"),
    ("bench.yml", "jobs/benchmarks-build/steps/[2]/with/key", "${{ hashFiles('**/Cargo.lock') }}"),
    ("bench.yml", "jobs/benchmarks-build/steps/[2]/with/key", "${{ runner.os }}"),
    ("bench.yml", "jobs/benchmarks-build/steps/[2]/with/path", "${{ runner.temp }}"),
    ("bench.yml", "jobs/benchmarks-build/steps/[2]/with/restore-keys", "${{ runner.os }}"),
    ("bench.yml", "jobs/benchmarks-build/steps/[3]/env/CARGO_TARGET_DIR", "${{ runner.temp }}"),
    ("bench.yml", "jobs/benchmarks/if", "${{ !startsWith(github.ref, 'refs/tags/') }}"),
    ("bench.yml", "jobs/benchmarks/steps/[3]/env/GH_TOKEN", "${{ secrets.BSV_SCRIPT_CORPUS_TOKEN }}"),
    ("bench.yml", "jobs/benchmarks/steps/[5]/with/key", "${{ hashFiles('Cargo.lock', 'tools/bench-compare/Cargo.lock') }}"),
    ("bench.yml", "jobs/benchmarks/steps/[5]/with/key", "${{ runner.os }}"),
    ("bench.yml", "jobs/benchmarks/steps/[5]/with/path", "${{ env.CARGO_TARGET_DIR }}"),
    ("bench.yml", "jobs/benchmarks/steps/[5]/with/restore-keys", "${{ runner.os }}"),
    ("bench.yml", "jobs/benchmarks/steps/[7]/env/RECORD_BASELINE", "${{ inputs.bench_baseline_record == true }}"),
    ("bench.yml", "jobs/benchmarks/steps/[8]/if", "always()"),
    ("bench.yml", "jobs/benchmarks/steps/[8]/with/name", "${{ runner.os }}"),
    ("bench.yml", "jobs/benchmarks/steps/[8]/with/path", "${{ runner.temp }}"),
    ("bench.yml", "jobs/benchmarks/steps/[8]/with/path", "${{ runner.temp }}"),
    ("bench.yml", "jobs/benchmarks/steps/[8]/with/path", "${{ runner.temp }}"),
    ("bench.yml", "jobs/benchmarks/steps/[8]/with/path", "${{ runner.temp }}"),
    ("bench.yml", "jobs/scoreboard/if", "always()"),
    ("bench.yml", "jobs/scoreboard/steps/[1]/with/path", "${{ runner.temp }}"),
    ("bench.yml", "jobs/scoreboard/steps/[2]/env/SCOREBOARD_COMMIT", "${{ github.sha }}"),
    ("bench.yml", "jobs/scoreboard/steps/[2]/env/SCOREBOARD_REPOSITORY", "${{ github.repository }}"),
    ("bench.yml", "jobs/scoreboard/steps/[2]/env/SCOREBOARD_RUN", "${{ github.run_id }}"),
    ("ci.yml", "concurrency/cancel-in-progress", "${{ !startsWith(github.ref, 'refs/tags/') }}"),
    ("ci.yml", "concurrency/group", "${{ github.event_name }}"),
    ("ci.yml", "concurrency/group", "${{ github.ref }}"),
    ("ci.yml", "jobs/beta-born/if", "github.event_name == 'pull_request' && github.base_ref == 'main'"),
    ("ci.yml", "jobs/beta-born/steps/[1]/env/PR_BASE", "${{ github.event.pull_request.base.sha }}"),
    ("ci.yml", "jobs/beta-born/steps/[1]/env/PR_HEAD", "${{ github.event.pull_request.head.sha }}"),
    ("ci.yml", "jobs/checks/env/BSV_CONFORMANCE_DIR", "${{ github.workspace }}"),
    ("ci.yml", "jobs/checks/steps/[10]/if", "${{ !cancelled() && steps.ready.outcome == 'success' }}"),
    ("ci.yml", "jobs/checks/steps/[11]/if", "${{ !cancelled() && steps.ready.outcome == 'success' }}"),
    ("ci.yml", "jobs/checks/steps/[12]/env/PR_BASE_SHA", "${{ github.event.pull_request.base.sha }}"),
    ("ci.yml", "jobs/checks/steps/[12]/if", "${{ !cancelled() && (steps.ready.outcome == 'success' || steps.plan.outputs.docs_only == 'true') }}"),
    ("ci.yml", "jobs/checks/steps/[13]/if", "${{ !cancelled() && steps.ready.outcome == 'success' }}"),
    ("ci.yml", "jobs/checks/steps/[14]/if", "${{ !cancelled() && steps.ready.outcome == 'success' }}"),
    ("ci.yml", "jobs/checks/steps/[15]/env/DOCS_ONLY", "${{ steps.plan.outputs.docs_only }}"),
    ("ci.yml", "jobs/checks/steps/[15]/env/VERDICTS", "${{ steps.docs.outcome }}"),
    ("ci.yml", "jobs/checks/steps/[15]/env/VERDICTS", "${{ steps.fixtures.outcome }}"),
    ("ci.yml", "jobs/checks/steps/[15]/env/VERDICTS", "${{ steps.front-page.outcome }}"),
    ("ci.yml", "jobs/checks/steps/[15]/env/VERDICTS", "${{ steps.front-pages.outcome }}"),
    ("ci.yml", "jobs/checks/steps/[15]/env/VERDICTS", "${{ steps.judge-tests.outcome }}"),
    ("ci.yml", "jobs/checks/steps/[15]/env/VERDICTS", "${{ steps.mutants-entries.outcome }}"),
    ("ci.yml", "jobs/checks/steps/[15]/env/VERDICTS", "${{ steps.secrets.outcome }}"),
    ("ci.yml", "jobs/checks/steps/[15]/env/VERDICTS", "${{ steps.vectors.outcome }}"),
    ("ci.yml", "jobs/checks/steps/[15]/env/VERDICTS", "${{ steps.wasm32.outcome }}"),
    ("ci.yml", "jobs/checks/steps/[15]/if", "${{ !cancelled() }}"),
    ("ci.yml", "jobs/checks/steps/[1]/env/EVENT", "${{ github.event_name }}"),
    ("ci.yml", "jobs/checks/steps/[2]/if", "steps.plan.outputs.docs_only != 'true'"),
    ("ci.yml", "jobs/checks/steps/[3]/if", "steps.plan.outputs.docs_only != 'true'"),
    ("ci.yml", "jobs/checks/steps/[4]/if", "steps.plan.outputs.docs_only != 'true'"),
    ("ci.yml", "jobs/checks/steps/[4]/with/save-if", "${{ github.event_name == 'push' && startsWith(github.ref, 'refs/heads/') }}"),
    ("ci.yml", "jobs/checks/steps/[5]/if", "steps.plan.outputs.docs_only != 'true'"),
    ("ci.yml", "jobs/checks/steps/[6]/if", "${{ !cancelled() && steps.ready.outcome == 'success' }}"),
    ("ci.yml", "jobs/checks/steps/[7]/if", "${{ !cancelled() && steps.ready.outcome == 'success' }}"),
    ("ci.yml", "jobs/checks/steps/[8]/if", "${{ !cancelled() && steps.ready.outcome == 'success' }}"),
    ("ci.yml", "jobs/checks/steps/[9]/if", "${{ !cancelled() && steps.ready.outcome == 'success' }}"),
    ("ci.yml", "jobs/dependent-check/if", "needs.dependents-plan.outputs.count != '0'"),
    ("ci.yml", "jobs/dependent-check/name", "${{ matrix.id }}"),
    ("ci.yml", "jobs/dependent-check/steps/[2]/env/READ_TOKEN", "${{ secrets.DEPENDENTS_READ_TOKEN }}"),
    ("ci.yml", "jobs/dependent-check/steps/[2]/if", "matrix.private"),
    ("ci.yml", "jobs/dependent-check/steps/[3]/with/ref", "${{ matrix.rev }}"),
    ("ci.yml", "jobs/dependent-check/steps/[3]/with/repository", "${{ matrix.repository }}"),
    ("ci.yml", "jobs/dependent-check/steps/[3]/with/token", "${{ matrix.private && secrets.DEPENDENTS_READ_TOKEN || github.token }}"),
    ("ci.yml", "jobs/dependent-check/steps/[5]/env/CONSUMER", "${{ matrix.id }}"),
    ("ci.yml", "jobs/dependent-check/strategy/matrix", "${{ fromJSON(needs.dependents-plan.outputs.matrix) }}"),
    ("ci.yml", "jobs/dependents-plan/if", "github.base_ref == 'main' || (github.event_name != 'pull_request' && !(github.event_name == 'push' && github.ref == 'refs/heads/beta'))"),
    ("ci.yml", "jobs/dependents-plan/outputs/count", "${{ steps.plan.outputs.count }}"),
    ("ci.yml", "jobs/dependents-plan/outputs/matrix", "${{ steps.plan.outputs.matrix }}"),
    ("ci.yml", "jobs/dependents-plan/steps/[2]/env/HAS_READ_TOKEN", "${{ secrets.DEPENDENTS_READ_TOKEN != '' }}"),
    ("ci.yml", "jobs/dependents/if", "always() && (github.base_ref == 'main' || (github.event_name != 'pull_request' && !(github.event_name == 'push' && github.ref == 'refs/heads/beta')))"),
    ("ci.yml", "jobs/dependents/steps/[0]/env/CHECK_RESULT", "${{ needs.dependent-check.result }}"),
    ("ci.yml", "jobs/dependents/steps/[0]/env/CONSUMER_COUNT", "${{ needs.dependents-plan.outputs.count }}"),
    ("ci.yml", "jobs/dependents/steps/[0]/env/PLAN_RESULT", "${{ needs.dependents-plan.result }}"),
    ("ci.yml", "jobs/lint/steps/[10]/env/BASE_REF", "${{ github.event.pull_request.base.sha || github.event.before }}"),
    ("ci.yml", "jobs/lint/steps/[10]/env/CARGO_TARGET_DIR", "${{ runner.temp }}"),
    ("ci.yml", "jobs/lint/steps/[10]/env/TMPDIR", "${{ runner.temp }}"),
    ("ci.yml", "jobs/lint/steps/[10]/if", "${{ !cancelled() && steps.ready.outcome == 'success' }}"),
    ("ci.yml", "jobs/lint/steps/[11]/env/DOCS_ONLY", "${{ steps.plan.outputs.docs_only }}"),
    ("ci.yml", "jobs/lint/steps/[11]/env/VERDICTS", "${{ steps.clippy.outcome }}"),
    ("ci.yml", "jobs/lint/steps/[11]/env/VERDICTS", "${{ steps.deny.outcome }}"),
    ("ci.yml", "jobs/lint/steps/[11]/env/VERDICTS", "${{ steps.fmt.outcome }}"),
    ("ci.yml", "jobs/lint/steps/[11]/env/VERDICTS", "${{ steps.ratchet.outcome }}"),
    ("ci.yml", "jobs/lint/steps/[11]/if", "${{ !cancelled() }}"),
    ("ci.yml", "jobs/lint/steps/[1]/env/EVENT", "${{ github.event_name }}"),
    ("ci.yml", "jobs/lint/steps/[2]/if", "steps.plan.outputs.docs_only != 'true'"),
    ("ci.yml", "jobs/lint/steps/[3]/if", "steps.plan.outputs.docs_only != 'true'"),
    ("ci.yml", "jobs/lint/steps/[4]/if", "steps.plan.outputs.docs_only != 'true'"),
    ("ci.yml", "jobs/lint/steps/[5]/if", "steps.plan.outputs.docs_only != 'true'"),
    ("ci.yml", "jobs/lint/steps/[5]/with/cache-directories", "${{ runner.temp }}"),
    ("ci.yml", "jobs/lint/steps/[5]/with/save-if", "${{ github.event_name == 'push' && startsWith(github.ref, 'refs/heads/') }}"),
    ("ci.yml", "jobs/lint/steps/[6]/if", "steps.plan.outputs.docs_only != 'true'"),
    ("ci.yml", "jobs/lint/steps/[7]/if", "${{ !cancelled() && steps.ready.outcome == 'success' }}"),
    ("ci.yml", "jobs/lint/steps/[8]/if", "${{ !cancelled() && steps.ready.outcome == 'success' }}"),
    ("ci.yml", "jobs/lint/steps/[9]/if", "${{ !cancelled() && steps.ready.outcome == 'success' }}"),
    ("ci.yml", "jobs/main-in-beta/if", "(github.event_name == 'pull_request' && github.base_ref == 'beta') || (github.event_name == 'push' && github.ref == 'refs/heads/beta') || (github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/sync/main-into-beta')"),
    ("ci.yml", "jobs/semver-tool-seed/if", "github.event_name == 'push' && startsWith(github.ref, 'refs/heads/')"),
    ("ci.yml", "jobs/semver-tool-seed/steps/[0]/with/key", "${{ runner.arch }}"),
    ("ci.yml", "jobs/semver-tool-seed/steps/[0]/with/key", "${{ runner.os }}"),
    ("ci.yml", "jobs/semver-tool-seed/steps/[0]/with/path", "${{ runner.temp }}"),
    ("ci.yml", "jobs/semver-tool-seed/steps/[1]/if", "steps.semver-tool.outputs.cache-hit != 'true'"),
    ("ci.yml", "jobs/semver-tool-seed/steps/[2]/if", "steps.semver-tool.outputs.cache-hit != 'true'"),
    ("ci.yml", "jobs/semver/if", "github.event_name == 'pull_request'"),
    ("ci.yml", "jobs/semver/steps/[1]/env/EVENT", "${{ github.event_name }}"),
    ("ci.yml", "jobs/semver/steps/[2]/if", "steps.plan.outputs.docs_only != 'true'"),
    ("ci.yml", "jobs/semver/steps/[3]/if", "steps.plan.outputs.docs_only != 'true'"),
    ("ci.yml", "jobs/semver/steps/[4]/if", "steps.plan.outputs.docs_only != 'true'"),
    ("ci.yml", "jobs/semver/steps/[4]/with/key", "${{ runner.arch }}"),
    ("ci.yml", "jobs/semver/steps/[4]/with/key", "${{ runner.os }}"),
    ("ci.yml", "jobs/semver/steps/[4]/with/path", "${{ runner.temp }}"),
    ("ci.yml", "jobs/semver/steps/[5]/if", "steps.plan.outputs.docs_only != 'true' && steps.semver-tool.outputs.cache-hit != 'true'"),
    ("ci.yml", "jobs/semver/steps/[6]/env/BASE_REF", "${{ github.base_ref }}"),
    ("ci.yml", "jobs/semver/steps/[6]/env/BASE_REV", "${{ github.event.pull_request.base.sha }}"),
    ("ci.yml", "jobs/semver/steps/[6]/env/GH_TOKEN", "${{ github.token }}"),
    ("ci.yml", "jobs/semver/steps/[6]/env/PR", "${{ github.event.pull_request.number }}"),
    ("ci.yml", "jobs/semver/steps/[6]/env/REPOSITORY", "${{ github.repository }}"),
    ("ci.yml", "jobs/semver/steps/[6]/if", "steps.plan.outputs.docs_only != 'true'"),
    ("ci.yml", "jobs/semver/steps/[7]/if", "steps.plan.outputs.docs_only == 'true'"),
    ("ci.yml", "jobs/sibling/env/CARGO_TARGET_DIR", "${{ github.workspace }}"),
    ("ci.yml", "jobs/sibling/if", "(github.event_name != 'pull_request' || github.base_ref == 'beta') && (github.event_name != 'push' || github.ref != 'refs/heads/main')"),
    ("ci.yml", "jobs/sibling/steps/[3]/with/ref", "${{ steps.pin.outputs.sibling }}"),
    ("ci.yml", "jobs/sibling/steps/[3]/with/repository", "${{ env.SIBLING_REPOSITORY }}"),
    ("ci.yml", "jobs/sibling/steps/[5]/with/save-if", "${{ github.event_name == 'push' && github.ref == 'refs/heads/beta' }}"),
    ("ci.yml", "jobs/sibling/steps/[6]/run", "${{ steps.pin.outputs.sibling }}"),
    ("ci.yml", "jobs/test/runs-on", "${{ matrix.os }}"),
    ("ci.yml", "jobs/test/steps/[10]/if", "steps.plan.outputs.whole == 'true'"),
    ("ci.yml", "jobs/test/steps/[11]/env/REACHED_TESTS", "${{ steps.plan.outputs.tests }}"),
    ("ci.yml", "jobs/test/steps/[11]/if", "steps.plan.outputs.whole != 'true' && steps.plan.outputs.reached != '0'"),
    ("ci.yml", "jobs/test/steps/[12]/if", "steps.plan.outputs.memory == 'true'"),
    ("ci.yml", "jobs/test/steps/[13]/if", "steps.plan.outputs.tracing == 'true'"),
    ("ci.yml", "jobs/test/steps/[14]/if", "steps.plan.outputs.doc == 'true'"),
    ("ci.yml", "jobs/test/steps/[15]/env/BSV_DOC_SUITE_LOG", "${{ runner.temp }}"),
    ("ci.yml", "jobs/test/steps/[15]/if", "steps.plan.outputs.doc == 'true'"),
    ("ci.yml", "jobs/test/steps/[16]/if", "steps.plan.outputs.build != 'true'"),
    ("ci.yml", "jobs/test/steps/[1]/env/EVENT", "${{ github.event_name }}"),
    ("ci.yml", "jobs/test/steps/[1]/env/GH_TOKEN", "${{ github.token }}"),
    ("ci.yml", "jobs/test/steps/[1]/env/PR", "${{ github.event.pull_request.number }}"),
    ("ci.yml", "jobs/test/steps/[1]/env/REPOSITORY", "${{ github.repository }}"),
    ("ci.yml", "jobs/test/steps/[2]/if", "steps.plan.outputs.build == 'true'"),
    ("ci.yml", "jobs/test/steps/[2]/with/toolchain", "${{ matrix.rust }}"),
    ("ci.yml", "jobs/test/steps/[3]/if", "steps.plan.outputs.build == 'true'"),
    ("ci.yml", "jobs/test/steps/[4]/if", "steps.plan.outputs.build == 'true'"),
    ("ci.yml", "jobs/test/steps/[5]/if", "steps.plan.outputs.build == 'true'"),
    ("ci.yml", "jobs/test/steps/[6]/if", "steps.plan.outputs.build == 'true'"),
    ("ci.yml", "jobs/test/steps/[6]/with/save-if", "${{ (github.event_name == 'pull_request' && steps.plan.outputs.whole == 'true') || (github.event_name == 'push' && (github.ref == 'refs/heads/beta' || github.ref == 'refs/heads/main')) }}"),
    ("ci.yml", "jobs/test/steps/[7]/if", "steps.plan.outputs.build == 'true'"),
    ("ci.yml", "jobs/test/steps/[8]/if", "github.event_name == 'pull_request' && steps.plan.outputs.build == 'true'"),
    ("ci.yml", "jobs/test/steps/[8]/run", "${{ steps.plan.outputs.file }}"),
    ("ci.yml", "jobs/test/steps/[9]/if", "steps.plan.outputs.lib == 'true'"),
    ("ci.yml", "jobs/test/strategy/matrix/os", "${{ fromJSON((github.event_name == 'workflow_dispatch' || startsWith(github.ref, 'refs/tags/')) && '[\"ubuntu-latest\", \"macos-15-intel\", \"windows-latest\"]' || '[\"ubuntu-latest\"]') }}"),
    ("ci.yml", "jobs/test/strategy/matrix/rust", "${{ fromJSON((github.event_name == 'workflow_dispatch' || startsWith(github.ref, 'refs/tags/')) && '[\"stable\", \"beta\"]' || '[\"stable\"]') }}"),
    ("docs.yml", "concurrency/group", "${{ github.event_name }}"),
    ("docs.yml", "concurrency/group", "${{ github.ref }}"),
    ("docs.yml", "jobs/doc-error-numbers/if", "github.event_name == 'workflow_dispatch'"),
    ("docs.yml", "jobs/doc-error-numbers/steps/[1]/with/toolchain", "${{ env.DOC_TOOLCHAIN }}"),
    ("features.yml", "concurrency/group", "${{ github.event_name }}"),
    ("features.yml", "concurrency/group", "${{ github.ref }}"),
    ("features.yml", "jobs/wasm32-slices/env/SLICE_NAME", "${{ matrix.consumer }}"),
    ("features.yml", "jobs/wasm32-slices/name", "${{ matrix.consumer }}"),
    ("front-pages.yml", "jobs/check/steps/[2]/env/GH_TOKEN", "${{ github.token }}"),
    ("front-pages.yml", "jobs/check/steps/[2]/env/WAIT", "${{ inputs.wait }}"),
    ("machete.yml", "concurrency/group", "${{ github.event_name }}"),
    ("machete.yml", "concurrency/group", "${{ github.ref }}"),
    ("msrv.yml", "concurrency/group", "${{ github.event_name }}"),
    ("msrv.yml", "concurrency/group", "${{ github.ref }}"),
    ("nightly.yml", "concurrency/group", "${{ github.ref }}"),
    ("nightly.yml", "env/FUZZ_MINUTES", "${{ vars.NIGHTLY_FUZZ_MINUTES || '10' }}"),
    ("nightly.yml", "jobs/bench/if", "${{ !cancelled() && inputs.weekly }}"),
    ("nightly.yml", "jobs/bench/steps/[0]/env/GH_TOKEN", "${{ github.token }}"),
    ("nightly.yml", "jobs/bench/steps/[0]/env/LINE", "${{ github.ref_name }}"),
    ("nightly.yml", "jobs/ci-full-beta/if", "${{ !cancelled() }}"),
    ("nightly.yml", "jobs/ci-full-beta/steps/[0]/env/GH_TOKEN", "${{ github.token }}"),
    ("nightly.yml", "jobs/ci-full-main/if", "${{ !cancelled() }}"),
    ("nightly.yml", "jobs/ci-full-main/steps/[0]/env/GH_TOKEN", "${{ github.token }}"),
    ("nightly.yml", "jobs/fuzz/env/FUZZ_SANITIZER", "${{ matrix.sanitizer || 'address' }}"),
    ("nightly.yml", "jobs/fuzz/if", "${{ !cancelled() && needs.source.result == 'success' }}"),
    ("nightly.yml", "jobs/fuzz/name", "${{ matrix.target }}"),
    ("nightly.yml", "jobs/fuzz/steps/[0]/with/ref", "${{ needs.source.outputs.commit }}"),
    ("nightly.yml", "jobs/fuzz/steps/[1]/with/toolchain", "${{ env.FUZZ_TOOLCHAIN }}"),
    ("nightly.yml", "jobs/fuzz/steps/[2]/with/key", "${{ env.FUZZ_TOOLCHAIN }}"),
    ("nightly.yml", "jobs/fuzz/steps/[2]/with/key", "${{ hashFiles('Cargo.toml', 'fuzz/Cargo.toml') }}"),
    ("nightly.yml", "jobs/fuzz/steps/[2]/with/key", "${{ runner.os }}"),
    ("nightly.yml", "jobs/fuzz/steps/[2]/with/restore-keys", "${{ env.FUZZ_TOOLCHAIN }}"),
    ("nightly.yml", "jobs/fuzz/steps/[2]/with/restore-keys", "${{ runner.os }}"),
    ("nightly.yml", "jobs/fuzz/steps/[4]/run", "${{ matrix.target }}"),
    ("nightly.yml", "jobs/fuzz/steps/[5]/run", "${{ matrix.target }}"),
    ("nightly.yml", "jobs/fuzz/steps/[5]/run", "${{ matrix.target }}"),
    ("nightly.yml", "jobs/fuzz/steps/[5]/run", "${{ matrix.target }}"),
    ("nightly.yml", "jobs/fuzz/steps/[6]/if", "always()"),
    ("nightly.yml", "jobs/fuzz/steps/[6]/with/name", "${{ matrix.target }}"),
    ("nightly.yml", "jobs/fuzz/steps/[6]/with/path", "${{ runner.temp }}"),
    ("nightly.yml", "jobs/fuzz/steps/[7]/if", "always()"),
    ("nightly.yml", "jobs/fuzz/steps/[7]/with/name", "${{ matrix.target }}"),
    ("nightly.yml", "jobs/fuzz/steps/[7]/with/path", "${{ runner.temp }}"),
    ("nightly.yml", "jobs/fuzz/steps/[8]/env/GH_REPO", "${{ github.repository }}"),
    ("nightly.yml", "jobs/fuzz/steps/[8]/env/GH_TOKEN", "${{ github.token }}"),
    ("nightly.yml", "jobs/fuzz/steps/[8]/env/RUN_URL", "${{ github.repository }}"),
    ("nightly.yml", "jobs/fuzz/steps/[8]/env/RUN_URL", "${{ github.run_id }}"),
    ("nightly.yml", "jobs/fuzz/steps/[8]/env/RUN_URL", "${{ github.server_url }}"),
    ("nightly.yml", "jobs/fuzz/steps/[8]/env/SOURCE_COMMIT", "${{ needs.source.outputs.commit }}"),
    ("nightly.yml", "jobs/fuzz/steps/[8]/env/TARGET", "${{ matrix.target }}"),
    ("nightly.yml", "jobs/fuzz/steps/[8]/if", "always()"),
    ("nightly.yml", "jobs/fuzz/strategy/max-parallel", "${{ fromJSON(needs.source.outputs.max_parallel_fuzz) }}"),
    ("nightly.yml", "jobs/mutants-tail/env/BSV_CONFORMANCE_DIR", "${{ github.workspace }}"),
    ("nightly.yml", "jobs/mutants-tail/env/LABEL", "${{ matrix.label }}"),
    ("nightly.yml", "jobs/mutants-tail/env/SHARD", "${{ matrix.shard }}"),
    ("nightly.yml", "jobs/mutants-tail/env/SOURCE_COMMIT", "${{ needs.source.outputs.commit }}"),
    ("nightly.yml", "jobs/mutants-tail/env/SURFACE", "${{ matrix.surface }}"),
    ("nightly.yml", "jobs/mutants-tail/if", "${{ !cancelled() && needs.source.result == 'success' && needs.source.outputs.shards_tail != '0' }}"),
    ("nightly.yml", "jobs/mutants-tail/name", "${{ matrix.shard }}"),
    ("nightly.yml", "jobs/mutants-tail/name", "${{ matrix.surface }}"),
    ("nightly.yml", "jobs/mutants-tail/steps/[0]/with/ref", "${{ needs.source.outputs.commit }}"),
    ("nightly.yml", "jobs/mutants-tail/steps/[11]/if", "always()"),
    ("nightly.yml", "jobs/mutants-tail/steps/[12]/if", "always()"),
    ("nightly.yml", "jobs/mutants-tail/steps/[12]/with/name", "${{ matrix.label }}"),
    ("nightly.yml", "jobs/mutants-tail/steps/[12]/with/path", "${{ runner.temp }}"),
    ("nightly.yml", "jobs/mutants-tail/steps/[6]/with/path", "${{ runner.temp }}"),
    ("nightly.yml", "jobs/mutants-tail/steps/[9]/env/MUTANTS_CEILING_MARKER", "${{ runner.temp }}"),
    ("nightly.yml", "jobs/mutants-tail/strategy/matrix/include", "${{ fromJSON(needs.source.outputs.matrix_tail) }}"),
    ("nightly.yml", "jobs/mutants-tail/strategy/max-parallel", "${{ fromJSON(needs.source.outputs.max_parallel_tail) }}"),
    ("nightly.yml", "jobs/mutants/env/BSV_CONFORMANCE_DIR", "${{ github.workspace }}"),
    ("nightly.yml", "jobs/mutants/env/LABEL", "${{ matrix.label }}"),
    ("nightly.yml", "jobs/mutants/env/SHARD", "${{ matrix.shard }}"),
    ("nightly.yml", "jobs/mutants/env/SOURCE_COMMIT", "${{ needs.source.outputs.commit }}"),
    ("nightly.yml", "jobs/mutants/env/SURFACE", "${{ matrix.surface }}"),
    ("nightly.yml", "jobs/mutants/if", "${{ needs.source.outputs.shards != '0' }}"),
    ("nightly.yml", "jobs/mutants/name", "${{ matrix.shard }}"),
    ("nightly.yml", "jobs/mutants/name", "${{ matrix.surface }}"),
    ("nightly.yml", "jobs/mutants/steps/[0]/with/ref", "${{ needs.source.outputs.commit }}"),
    ("nightly.yml", "jobs/mutants/steps/[11]/if", "always()"),
    ("nightly.yml", "jobs/mutants/steps/[12]/if", "always()"),
    ("nightly.yml", "jobs/mutants/steps/[12]/with/name", "${{ matrix.label }}"),
    ("nightly.yml", "jobs/mutants/steps/[12]/with/path", "${{ runner.temp }}"),
    ("nightly.yml", "jobs/mutants/steps/[6]/with/path", "${{ runner.temp }}"),
    ("nightly.yml", "jobs/mutants/steps/[9]/env/MUTANTS_CEILING_MARKER", "${{ runner.temp }}"),
    ("nightly.yml", "jobs/mutants/strategy/matrix/include", "${{ fromJSON(needs.source.outputs.matrix) }}"),
    ("nightly.yml", "jobs/mutants/strategy/max-parallel", "${{ fromJSON(needs.source.outputs.max_parallel) }}"),
    ("nightly.yml", "jobs/mutation-score/if", "${{ always() && needs.source.result == 'success' }}"),
    ("nightly.yml", "jobs/mutation-score/steps/[0]/with/ref", "${{ needs.source.outputs.commit }}"),
    ("nightly.yml", "jobs/mutation-score/steps/[1]/with/path", "${{ runner.temp }}"),
    ("nightly.yml", "jobs/mutation-score/steps/[2]/if", "${{ needs.source.outputs.shards != '0' }}"),
    ("nightly.yml", "jobs/mutation-score/steps/[2]/with/path", "${{ runner.temp }}"),
    ("nightly.yml", "jobs/mutation-score/steps/[3]/env/SOURCE_COMMIT", "${{ needs.source.outputs.commit }}"),
    ("nightly.yml", "jobs/mutation-score/steps/[3]/if", "always()"),
    ("nightly.yml", "jobs/mutation-score/steps/[4]/if", "always()"),
    ("nightly.yml", "jobs/mutation-score/steps/[4]/with/path", "${{ runner.temp }}"),
    ("nightly.yml", "jobs/mutation-score/steps/[5]/if", "always()"),
    ("nightly.yml", "jobs/mutation-score/steps/[5]/with/path", "${{ runner.temp }}"),
    ("nightly.yml", "jobs/mutation-score/steps/[5]/with/path", "${{ runner.temp }}"),
    ("nightly.yml", "jobs/source/outputs/commit", "${{ steps.source.outputs.commit }}"),
    ("nightly.yml", "jobs/source/outputs/matrix", "${{ steps.plan.outputs.matrix }}"),
    ("nightly.yml", "jobs/source/outputs/matrix_tail", "${{ steps.plan.outputs.matrix_tail }}"),
    ("nightly.yml", "jobs/source/outputs/max_parallel", "${{ steps.plan.outputs.max_parallel }}"),
    ("nightly.yml", "jobs/source/outputs/max_parallel_fuzz", "${{ steps.plan.outputs.max_parallel_fuzz }}"),
    ("nightly.yml", "jobs/source/outputs/max_parallel_reason", "${{ steps.plan.outputs.max_parallel_reason }}"),
    ("nightly.yml", "jobs/source/outputs/max_parallel_tail", "${{ steps.plan.outputs.max_parallel_tail }}"),
    ("nightly.yml", "jobs/source/outputs/mode", "${{ steps.plan.outputs.mode }}"),
    ("nightly.yml", "jobs/source/outputs/shards", "${{ steps.plan.outputs.shards }}"),
    ("nightly.yml", "jobs/source/outputs/shards_tail", "${{ steps.plan.outputs.shards_tail }}"),
    ("nightly.yml", "jobs/source/steps/[0]/with/ref", "${{ inputs.commit || github.sha }}"),
    ("nightly.yml", "jobs/source/steps/[1]/env/COMMIT", "${{ inputs.commit || github.sha }}"),
    ("nightly.yml", "jobs/source/steps/[1]/env/LINE", "${{ github.ref_name }}"),
    ("nightly.yml", "jobs/source/steps/[2]/env/TMPDIR", "${{ runner.temp }}"),
    ("nightly.yml", "jobs/source/steps/[5]/env/COMMIT", "${{ steps.source.outputs.commit }}"),
    ("nightly.yml", "jobs/source/steps/[5]/env/GH_TOKEN", "${{ github.token }}"),
    ("nightly.yml", "jobs/source/steps/[5]/env/LINE", "${{ github.ref_name }}"),
    ("nightly.yml", "jobs/source/steps/[5]/if", "${{ inputs.mode != 'complete' }}"),
    ("nightly.yml", "jobs/source/steps/[6]/env/COMMIT", "${{ steps.source.outputs.commit }}"),
    ("nightly.yml", "jobs/source/steps/[6]/env/HEAVY_MAX_PARALLEL", "${{ inputs.heavy_max_parallel }}"),
    ("nightly.yml", "jobs/source/steps/[6]/env/MODE", "${{ inputs.mode || 'incremental' }}"),
    ("nightly.yml", "jobs/source/steps/[7]/env/LOCKFILE", "${{ steps.plan.outputs.lockfile }}"),
    ("nightly.yml", "jobs/source/steps/[8]/with/path", "${{ runner.temp }}"),
    ("release.yml", "concurrency/group", "${{ github.ref }}"),
    ("release.yml", "jobs/bench/secrets/BSV_SCRIPT_CORPUS_TOKEN", "${{ secrets.BSV_SCRIPT_CORPUS_TOKEN }}"),
    ("release.yml", "jobs/ci/secrets/DEPENDENTS_READ_TOKEN", "${{ secrets.DEPENDENTS_READ_TOKEN }}"),
    ("release.yml", "jobs/front-pages/steps/[1]/env/GH_TOKEN", "${{ github.token }}"),
    ("release.yml", "jobs/page/steps/[2]/env/GH_TOKEN", "${{ github.token }}"),
    ("release.yml", "jobs/page/steps/[3]/env/GH_TOKEN", "${{ github.token }}"),
    ("release.yml", "jobs/publish/steps/[4]/env/CARGO_REGISTRY_TOKEN", "${{ steps.auth.outputs.token }}"),
    ("release.yml", "jobs/version/steps/[6]/env/GH_TOKEN", "${{ github.token }}"),
    ("sibling-judge.yml", "concurrency/group", "${{ github.event.workflow_run.head_sha || inputs.run_id }}"),
    ("sibling-judge.yml", "jobs/judge/if", "github.ref == 'refs/heads/main'"),
    ("sibling-judge.yml", "jobs/judge/outputs/attempt", "${{ steps.judge.outputs.attempt }}"),
    ("sibling-judge.yml", "jobs/judge/outputs/conclusion", "${{ steps.judge.outputs.conclusion }}"),
    ("sibling-judge.yml", "jobs/judge/outputs/post", "${{ steps.judge.outputs.post }}"),
    ("sibling-judge.yml", "jobs/judge/outputs/run", "${{ steps.judge.outputs.run }}"),
    ("sibling-judge.yml", "jobs/judge/outputs/text", "${{ steps.judge.outputs.text }}"),
    ("sibling-judge.yml", "jobs/judge/outputs/title", "${{ steps.judge.outputs.title }}"),
    ("sibling-judge.yml", "jobs/judge/steps/[1]/env/ATTEMPT", "${{ github.event.workflow_run.run_attempt }}"),
    ("sibling-judge.yml", "jobs/judge/steps/[1]/env/GH_TOKEN", "${{ github.token }}"),
    ("sibling-judge.yml", "jobs/judge/steps/[1]/env/REPOSITORY_ID", "${{ github.repository_id }}"),
    ("sibling-judge.yml", "jobs/judge/steps/[1]/env/RUN_ID", "${{ github.event.workflow_run.id || inputs.run_id }}"),
    ("sibling-judge.yml", "jobs/judge/steps/[1]/env/WORKFLOW_SHA", "${{ github.workflow_sha }}"),
    ("sibling-judge.yml", "jobs/report/if", "always() && github.ref == 'refs/heads/main'"),
    ("sibling-judge.yml", "jobs/report/steps/[1]/env/GH_TOKEN", "${{ github.token }}"),
    ("sibling-judge.yml", "jobs/report/steps/[1]/env/REPOSITORY_ID", "${{ github.repository_id }}"),
    ("sibling-judge.yml", "jobs/report/steps/[1]/env/RUN_ID", "${{ github.event.workflow_run.id || inputs.run_id }}"),
    ("sibling-judge.yml", "jobs/report/steps/[2]/if", "steps.owed.outcome != 'success' || steps.owed.outputs.owed != 'no'"),
    ("sibling-judge.yml", "jobs/report/steps/[2]/with/app-id", "${{ vars.SIBLING_JUDGE_APP_ID }}"),
    ("sibling-judge.yml", "jobs/report/steps/[2]/with/private-key", 
    // the App's key, written in two parts: its text whole is the token step's alone
    // (`arch_ci_sibling_judge_97.rs`)
    concat!("${{ secrets.", "SIBLING_JUDGE_KEY }}")),
    ("sibling-judge.yml", "jobs/report/steps/[3]/env/APP_ID", "${{ vars.SIBLING_JUDGE_APP_ID }}"),
    ("sibling-judge.yml", "jobs/report/steps/[3]/env/ATTEMPT", "${{ github.event.workflow_run.run_attempt }}"),
    ("sibling-judge.yml", "jobs/report/steps/[3]/env/CONCLUSION", "${{ needs.judge.outputs.conclusion }}"),
    ("sibling-judge.yml", "jobs/report/steps/[3]/env/DETAILS_URL", "${{ github.repository }}"),
    ("sibling-judge.yml", "jobs/report/steps/[3]/env/DETAILS_URL", "${{ github.run_id }}"),
    ("sibling-judge.yml", "jobs/report/steps/[3]/env/DETAILS_URL", "${{ github.server_url }}"),
    ("sibling-judge.yml", "jobs/report/steps/[3]/env/GH_TOKEN", "${{ steps.token.outputs.token }}"),
    ("sibling-judge.yml", "jobs/report/steps/[3]/env/JUDGED_ATTEMPT", "${{ needs.judge.outputs.attempt }}"),
    ("sibling-judge.yml", "jobs/report/steps/[3]/env/JUDGED_RUN", "${{ needs.judge.outputs.run }}"),
    ("sibling-judge.yml", "jobs/report/steps/[3]/env/JUDGE_RESULT", "${{ needs.judge.result }}"),
    ("sibling-judge.yml", "jobs/report/steps/[3]/env/POST", "${{ needs.judge.outputs.post }}"),
    ("sibling-judge.yml", "jobs/report/steps/[3]/env/REPOSITORY_ID", "${{ github.repository_id }}"),
    ("sibling-judge.yml", "jobs/report/steps/[3]/env/RUN_ID", "${{ github.event.workflow_run.id || inputs.run_id }}"),
    ("sibling-judge.yml", "jobs/report/steps/[3]/env/TEXT", "${{ needs.judge.outputs.text }}"),
    ("sibling-judge.yml", "jobs/report/steps/[3]/env/TITLE", "${{ needs.judge.outputs.title }}"),
    ("sibling-judge.yml", "jobs/report/steps/[3]/if", "steps.owed.outcome != 'success' || steps.owed.outputs.owed != 'no'"),
    ("sibling-judge.yml", "run-name", "${{ github.event.workflow_run.head_sha || format('of run {0}', inputs.run_id) }}"),
    ("sibling-run.yml", "concurrency/group", "${{ github.event_name }}"),
    ("sibling-run.yml", "concurrency/group", "${{ github.ref }}"),
    ("sibling-run.yml", "jobs/raw/env/CARGO_TARGET_DIR", "${{ github.workspace }}"),
    ("sibling-run.yml", "jobs/raw/steps/[0]/with/ref", "${{ github.event.pull_request.head.sha || github.sha }}"),
    ("sibling-run.yml", "jobs/raw/steps/[3]/with/ref", "${{ steps.pin.outputs.sibling }}"),
    ("sibling-run.yml", "jobs/raw/steps/[6]/env/HEAD_SHA", "${{ github.event.pull_request.head.sha || github.sha }}"),
    ("sibling-run.yml", "jobs/raw/steps/[6]/env/PIN", "${{ steps.pin.outputs.sibling }}"),
    ("sibling-run.yml", "jobs/raw/steps/[6]/env/PULL_REQUEST", "${{ github.event.pull_request.number }}"),
    ("sibling-run.yml", "jobs/raw/steps/[7]/if", "always()"),
    ("sibling-run.yml", "jobs/raw/steps/[7]/with/path", "${{ runner.temp }}"),
    ("sibling-run.yml", "run-name", "${{ github.event.pull_request.head.sha || github.sha }}"),
    ("sync-main-into-beta.yml", "jobs/sync/steps/[2]/env/GH_TOKEN", "${{ github.token }}"),
    ("sync-main-into-beta.yml", "jobs/sync/steps/[2]/env/LEASE", "${{ steps.pick.outputs.lease }}"),
    ("sync-main-into-beta.yml", "jobs/sync/steps/[2]/if", "steps.pick.outputs.push == 'true'"),
    ("sync-main-into-beta.yml", "jobs/sync/steps/[3]/env/BODY", "${{ steps.pick.outputs.body }}"),
    ("sync-main-into-beta.yml", "jobs/sync/steps/[3]/env/GH_TOKEN", "${{ github.token }}"),
    ("sync-main-into-beta.yml", "jobs/sync/steps/[3]/env/STATE", "${{ steps.pick.outputs.state }}"),
    ("sync-main-into-beta.yml", "jobs/sync/steps/[3]/env/TITLE", "${{ steps.pick.outputs.title }}"),
    ("sync-main-into-beta.yml", "jobs/sync/steps/[3]/if", "steps.pick.outputs.state != 'synced'"),
    ("sync-main-into-beta.yml", "jobs/sync/steps/[4]/env/GH_TOKEN", "${{ github.token }}"),
    ("sync-main-into-beta.yml", "jobs/sync/steps/[4]/if", "steps.pick.outputs.push == 'true'"),
    ("sync-main-into-beta.yml", "jobs/sync/steps/[5]/env/GH_TOKEN", "${{ github.token }}"),
    ("sync-main-into-beta.yml", "jobs/sync/steps/[5]/if", "steps.pick.outputs.push == 'true'"),
];
/// The rows of [`EXPRESSIONS`] that hand a job a repository secret, chosen by hand by the
/// reader of this file (no matcher reads an expression's meaning): each is held in
/// [`EXPRESSIONS`], and each job holding one is pinned whole by [`HOLDERS`].
const SECRETS: [(&str, &str, &str); 7] = [
    (
        "bench.yml",
        "jobs/benchmarks/steps/[3]/env/GH_TOKEN",
        "${{ secrets.BSV_SCRIPT_CORPUS_TOKEN }}",
    ),
    (
        "ci.yml",
        "jobs/dependent-check/steps/[2]/env/READ_TOKEN",
        "${{ secrets.DEPENDENTS_READ_TOKEN }}",
    ),
    (
        "ci.yml",
        "jobs/dependent-check/steps/[3]/with/token",
        "${{ matrix.private && secrets.DEPENDENTS_READ_TOKEN || github.token }}",
    ),
    (
        "ci.yml",
        "jobs/dependents-plan/steps/[2]/env/HAS_READ_TOKEN",
        "${{ secrets.DEPENDENTS_READ_TOKEN != '' }}",
    ),
    (
        "release.yml",
        "jobs/bench/secrets/BSV_SCRIPT_CORPUS_TOKEN",
        "${{ secrets.BSV_SCRIPT_CORPUS_TOKEN }}",
    ),
    (
        "release.yml",
        "jobs/ci/secrets/DEPENDENTS_READ_TOKEN",
        "${{ secrets.DEPENDENTS_READ_TOKEN }}",
    ),
    (
        "sibling-judge.yml",
        "jobs/report/steps/[2]/with/private-key",
        // the App's key, written in two parts: its text whole is the token step's alone
        // (`arch_ci_sibling_judge_97.rs`)
        concat!("${{ secrets.", "SIBLING_JUDGE_KEY }}"),
    ),
];
/// Every job holding a grant or a secret the file does not bound, by a digest of its pairs.
const HOLDERS: [(&str, &str, &str); 12] = [
    ("advisories.yml", "jobs/advisories", "2ec253284acac6a2"),
    ("bench.yml", "jobs/benchmarks", "65975bcfc5996a18"),
    ("ci.yml", "jobs/dependent-check", "b754c9adce2b769c"),
    ("ci.yml", "jobs/dependents-plan", "af2ecb812e805302"),
    ("nightly.yml", "jobs/bench", "175a84655d37e2bf"),
    ("nightly.yml", "jobs/ci-full-beta", "cdfeccec3cb6cff9"),
    ("nightly.yml", "jobs/ci-full-main", "9a4d0b920429e552"),
    ("nightly.yml", "jobs/fuzz", "f787a543ea86aa7a"),
    ("release.yml", "jobs/bench", "e2c55c663dffc2f5"),
    ("release.yml", "jobs/ci", "66b0d55aa2fdcd5a"),
    ("sibling-judge.yml", "jobs/report", "3d811e33fafd9fd7"),
    ("sync-main-into-beta.yml", "jobs/sync", "a6d5ff73ab9880a0"),
];

/// The literal text a group's name opens with, up to its earliest expression.
fn head(value: &str) -> &str {
    value.find("${{").map_or(value, |at| &value[..at])
}

#[test]
fn no_two_files_groups_can_meet_whatever_their_expressions_give_1034() {
    let groups: Vec<(&str, &str)> = GROUPS
        .iter()
        .filter(|(_, p, _)| p.ends_with("concurrency") || p.ends_with("concurrency/group"))
        .map(|(f, _, v)| (*f, *v))
        .collect();
    assert!(groups.len() >= 12, "{groups:?}");
    for (a, x) in &groups {
        assert!(
            !head(x).is_empty(),
            "{a}: a group opening with an expression: {x}"
        );
        for (b, y) in &groups {
            if a != b {
                let (hx, hy) = (head(x), head(y));
                let whole = |h: &str, v: &str| h.len() == v.len();
                assert!(
                    !(hy.starts_with(hx) && !whole(hx, x)
                        || hx.starts_with(hy) && !whole(hy, y)
                        || x == y),
                    "{a}'s group {x:?} and {b}'s {y:?} can name one group"
                );
            }
        }
    }
}

#[test]
fn a_step_added_to_a_job_holding_a_grant_or_a_secret_is_refused_by_holders_1034() {
    let files = files();
    let holders: Vec<&(&str, &str, &str)> = HOLDERS.iter().collect();
    assert!(holders.len() >= 8, "{holders:?}");
    for (file, job, _) in holders {
        let id = job.strip_prefix("jobs/").expect("a job");
        let copy = planted(&files, file, |t| {
            let key = format!("\n  {id}:\n");
            let at = t.find(&key).expect("the job") + key.len();
            format!("{}    env:\n      X: gh run cancel\n{}", &t[..at], &t[at..])
        });
        refused_by(&set_errors(&copy), "HOLDERS");
    }
    // the fold's own plant: a step that cancels a run, in a job whose grant already stands
    let copy = planted(&files, "nightly.yml", |t| {
        t.replacen(
            "    steps:\n",
            "    steps:\n      - name: x\n        run: gh run cancel 1\n",
            1,
        )
    });
    let errors = set_errors(&copy);
    refused_by(&errors, "HOLDERS");
    // the step holds no expression: beside HOLDERS only the later steps' expressions, moved
    // one index down, are named
    assert!(
        errors
            .iter()
            .all(|e| e.starts_with("HOLDERS: ") || e.starts_with("EXPRESSIONS: ")),
        "{errors:?}"
    );
}

#[test]
fn the_hand_chosen_secrets_are_rows_of_the_pinned_expressions_1034() {
    for row in &SECRETS {
        assert!(
            EXPRESSIONS.contains(row),
            "{row:?} is no row of EXPRESSIONS"
        );
    }
    // a string's `}}` does not close its expression; an unclosed one runs to the value's end
    let pair = |v: &str| vec![("jobs/a/env/X".to_owned(), v.to_owned())];
    let texts = |v: &str| -> Vec<String> {
        expressions("f", &pair(v))
            .into_iter()
            .map(|(_, _, e)| e)
            .collect()
    };
    assert_eq!(
        texts("a ${{ '}}' || secrets.X }} b"),
        ["${{ '}}' || secrets.X }}"]
    );
    assert_eq!(
        texts("${{ 'it''s }}' }}${{ x"),
        ["${{ 'it''s }}' }}", "${{ x"]
    );
    // a conditional's whole value, delimited or bare
    let cond = vec![("jobs/a/steps/[0]/if".to_owned(), "always()".to_owned())];
    assert_eq!(expressions("f", &cond).len(), 1);
}

#[test]
fn the_re_reads_secret_and_token_spellings_are_refused_by_expressions_1034() {
    let files = files();
    for spelling in ["${{ toJSON(secrets) }}", "${{ github['token'] }}"] {
        let copy = planted(&files, "docs.yml", |t| {
            format!("{t}  leak:\n    runs-on: ubuntu-latest\n    env:\n      ALL: {spelling}\n    steps:\n      - run: true\n")
        });
        let errors = set_errors(&copy);
        refused_by(&errors, "EXPRESSIONS");
        assert!(
            errors.iter().any(|e| e.contains(spelling)),
            "{spelling}: {errors:?}"
        );
    }
}

/// The functions of the platform's expressions page, the contexts a workflow names, and the
/// forms an expression reads a value by.
const FUNCTIONS: [&str; 13] = [
    "contains",
    "startsWith",
    "endsWith",
    "format",
    "join",
    "toJSON",
    "fromJSON",
    "hashFiles",
    "case",
    "success",
    "always",
    "cancelled",
    "failure",
];
const CONTEXTS: [&str; 12] = [
    "github", "env", "vars", "job", "jobs", "steps", "runner", "secrets", "strategy", "matrix",
    "needs", "inputs",
];

/// Generated expressions over every function, context and form, each planted where the
/// platform reads one (a job's `env`, a step's `with`, a run block, a conditional with and
/// without delimiters, a folded block split over two lines), and every pinned expression
/// changed by one character: each RED by `EXPRESSIONS` (the differential under the lane's logs
/// runs the same through a real parser in every emitter style).
#[test]
fn every_added_or_changed_expression_is_refused_by_expressions_1034() {
    let files = files();
    let mut forms = Vec::new();
    for c in CONTEXTS {
        forms.push(format!("{c}.token"));
        forms.push(format!("{c}['token']"));
        forms.push(format!("{c}.*.name"));
        for f in FUNCTIONS {
            forms.push(format!("{f}({c})"));
        }
    }
    let mut planted_count = 0;
    for form in &forms {
        for site in [
            format!("    env:\n      X: ${{{{ {form} }}}}\n    steps:\n      - run: true\n"),
            format!("    steps:\n      - uses: a/b@0123456789012345678901234567890123456789\n        with:\n          x: pre-${{{{ {form} }}}}\n"),
            format!("    steps:\n      - run: |\n          echo ${{{{ {form} }}}}\n"),
            format!("    steps:\n      - run: >\n          echo ${{{{\n          {form} }}}}\n"),
            format!("    if: ${{{{ {form} }}}}\n    steps:\n      - run: true\n"),
            format!("    steps:\n      - if: {form}\n        run: true\n"),
        ] {
            let copy = planted(&files, "docs.yml", |t| {
                format!("{t}  planted:\n    runs-on: ubuntu-latest\n{site}")
            });
            let name = &copy.iter().find(|(n, _)| n == "docs.yml").expect("docs").1;
            assert_eq!(style_errors("docs.yml", name), Vec::<String>::new(), "{site}");
            refused_by(&set_errors(&copy), "EXPRESSIONS");
            planted_count += 1;
        }
    }
    assert!(planted_count >= 1_000, "{planted_count}");
    // every pinned expression of every file changed by one character
    let mut changed = 0;
    for (file, text) in &files {
        let pairs = key_paths(text);
        for (_, path, expr) in expressions(file, &pairs) {
            if path.ends_with("/if") && !expr.contains("${{") && expr.is_empty() {
                continue;
            }
            let Some(at) = text.find(expr.lines().next().unwrap_or(&expr)) else {
                continue;
            };
            let copy = planted(&files, file, |t| {
                let mut s = t.to_owned();
                let first = expr.lines().next().unwrap_or(&expr);
                let mid = at + first.len().min(4);
                let mid = (mid..=at + first.len())
                    .find(|m| s.is_char_boundary(*m))
                    .unwrap_or(at);
                s.insert(mid, 'q');
                s
            });
            let errors = set_errors(&copy);
            if errors.is_empty() {
                panic!("{file} {path}: {expr:?} changed passed");
            }
            refused_by(&errors, "EXPRESSIONS");
            changed += 1;
        }
    }
    assert!(changed >= 300, "{changed}");
}

/// The fold's own three plants: an expression split over a folded block's lines (read joined,
/// as the parser folds it), a matrix value that is an expression, a conditional as a bare word;
/// each RED by `EXPRESSIONS`. A matrix value with no `${{` read by an expression already pinned
/// is no expression: the platform evaluates the expression that reads it, and the value is its
/// result's data (the stated bound of the lane record, its own assertion here).
#[test]
fn the_folds_own_plants_are_refused_or_stated_1034() {
    let files = files();
    let folded = planted(&files, "docs.yml", |t| {
        format!("{t}  planted:\n    runs-on: ubuntu-latest\n    steps:\n      - run: >-\n          echo ${{{{ secrets.\n          ANY }}}}\n")
    });
    let errors = set_errors(&folded);
    assert!(
        errors
            .iter()
            .any(|e| e.starts_with("EXPRESSIONS: ") && e.contains("${{ secrets. ANY }}")),
        "{errors:?}"
    );
    let matrix = planted(&files, "features.yml", |t| {
        t.replacen(
            "overlay, relay]",
            "overlay, relay, '${{ secrets.ANY }}']",
            1,
        )
    });
    refused_by(&set_errors(&matrix), "EXPRESSIONS");
    let bare = planted(&files, "docs.yml", |t| {
        t.replacen("    steps:\n", "    if: true\n    steps:\n", 1)
    });
    refused_by(&set_errors(&bare), "EXPRESSIONS");
    // stated: a word with no `${{` added to a matrix an expression reads
    let data = planted(&files, "features.yml", |t| {
        t.replacen("overlay, relay]", "overlay, relay, secrets.ANY]", 1)
    });
    assert!(
        set_errors(&data).is_empty(),
        "a matrix value with no expression is now judged: move the bound out of the lane record"
    );
}
