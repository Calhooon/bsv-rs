//! The daily advisories run's three answers, each shown by a run of the pinned tool (#1034's
//! second fold).
//!
//! `advisories.yml` reads a graph as clean (cargo-deny exits 0), as a finding (an advisory's
//! `error[...]`: the line's issue opened or rewritten, its text naming the advisory ids) or as
//! not judged (cargo-deny failed otherwise: the run red, the issue left as it stands). Which
//! branch an answer takes is decided by the issue step's lines from `findings=""` to the line
//! before its issue lookup, and those lines read nothing but the three logs and exit codes
//! the advisories step writes under `$RUNNER_TEMP`. So this file lifts those lines out of the
//! workflow as it stands, runs them under `bash` with `$RUNNER_TEMP` pointed at a recorded
//! state, and reads the branch they took: no network, no `gh`, no git.
//!
//! The states under `tests/data/advisories_1034/` are the logs and codes of cargo-deny
//! 0.20.2 (the release binary the workflows install, its sha256 checked) run by the
//! advisories step's own lines, lifted from the workflow, on a copy of the tree with one
//! change each (the tree's paths rewritten to a runner's): the tree as it is; `deny.toml`
//! with a syntax error; `deny.toml` naming a key `[advisories]` does not have; the advisory
//! database at a URL that cannot answer (an `.invalid` host, a fresh `db-path`); the lock with
//! `slab` moved to 0.4.10 (RUSTSEC-2025-0047, and yanked); and the tree and that lock on a
//! toolchain with no `wasm32-unknown-unknown` installed. Until this fold an unknown key was
//! read as a finding (`error[unexpected-keys]`), so a config the tool could not read would
//! have opened an issue that reads as an advisory.
//!
//! The lines are a bash script and use `grep -E`, `sed -E` and `paste`, as the runner does, so
//! each test returns at once on Windows (where `bash` may be another program) and says so; the
//! Linux cell of the required set runs them on every pull request, a macOS host by hand.
#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

const DAILY: &str = ".github/workflows/advisories.yml";
const FIXTURES: &str = "tests/data/advisories_1034";

/// The branch the decision lines took on one state.
#[derive(Debug, PartialEq, Eq)]
enum Branch {
    Clean,
    /// The findings' text, one line a graph, as the issue would carry it.
    Finding(String),
    /// The `::error::` line of a run that could not judge.
    NotJudged(String),
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    std::fs::read_to_string(root().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The issue step's decision lines: from `findings=""` to the line before the issue lookup's
/// comment, the step's indentation removed.
fn decision_lines(daily: &str) -> String {
    let step = daily
        .split("      - name: Open, rewrite or close the line's issue\n")
        .nth(1)
        .expect("the issue step");
    let from = step
        .find("          findings=\"\"\n")
        .expect("`findings=\"\"`");
    let to = step
        .find("          # Every page of the open issues")
        .expect("the issue lookup's comment");
    assert!(from < to, "the decision lines are not ahead of the lookup");
    step[from..to]
        .lines()
        .map(|line| line.strip_prefix("          ").unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Runs the decision lines of `daily` on the recorded state `dir`, under the step's own
/// `set -euo pipefail`.
/// `true` where the decision lines cannot be run as the runner runs them.
fn not_here() -> bool {
    if cfg!(windows) {
        eprintln!("skipped on Windows: the decision lines are run under bash on Unix alone");
    }
    cfg!(windows)
}

fn decide(daily: &str, dir: &Path) -> Branch {
    let script = format!(
        "set -euo pipefail\n{}\nif [[ -n \"$findings\" ]]; then echo BRANCH-FINDING; printf '%s' \"$findings\"; else echo BRANCH-CLEAN; fi\n",
        decision_lines(daily)
    );
    let out = Command::new("bash")
        .arg("-c")
        .arg(&script)
        .env("RUNNER_TEMP", dir)
        .env("LINE", "beta")
        .output()
        .expect("bash");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    match out.status.code() {
        Some(0) => match stdout.split_once('\n') {
            Some(("BRANCH-CLEAN", "")) => Branch::Clean,
            Some(("BRANCH-FINDING", text)) => Branch::Finding(text.to_owned()),
            _ => panic!("{}: an answer of no branch: {stdout:?}", dir.display()),
        },
        Some(1) if stdout.starts_with("::error::cargo-deny could not judge:") => {
            Branch::NotJudged(stdout.trim_end().to_owned())
        }
        code => panic!(
            "{}: exit {code:?}: {stdout:?} {:?}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr)
        ),
    }
}

fn state(name: &str) -> PathBuf {
    let dir = root().join(FIXTURES).join(name);
    assert!(dir.is_dir(), "{}: no such recorded state", dir.display());
    dir
}

const NOT_JUDGED: &str = "::error::cargo-deny could not judge: all wasm32 default (it failed with no advisory's finding, or with a fault of its own). This run could not judge `beta`; its issue is left as it stands";

/// The findings' text of a state whose three graphs each carry the planted `slab` 0.4.10.
const SLAB: &str = "- `all`: vulnerability: 1, yanked: 1; advisory ids: RUSTSEC-2025-0047\n- `wasm32`: vulnerability: 1, yanked: 1; advisory ids: RUSTSEC-2025-0047\n- `default`: vulnerability: 1, yanked: 1; advisory ids: RUSTSEC-2025-0047\n";

/// Every recorded state and the branch it must take: `(state, branch)`.
fn table() -> Vec<(&'static str, Branch)> {
    vec![
        ("a_clean", Branch::Clean),
        (
            "b_toml_syntax_error",
            Branch::NotJudged(NOT_JUDGED.to_owned()),
        ),
        (
            "c_unknown_advisories_key",
            Branch::NotJudged(NOT_JUDGED.to_owned()),
        ),
        (
            "d_database_unreachable",
            Branch::NotJudged(NOT_JUDGED.to_owned()),
        ),
        ("e_advisory_in_the_lock", Branch::Finding(SLAB.to_owned())),
        ("f_wasm32_target_absent", Branch::Clean),
        (
            "f_wasm32_target_absent_advisory",
            Branch::Finding(SLAB.to_owned()),
        ),
    ]
}

#[test]
fn each_recorded_answer_of_cargo_deny_takes_its_branch_1034() {
    if not_here() {
        return;
    }
    let daily = read(DAILY);
    let wrong: Vec<String> = table()
        .into_iter()
        .filter_map(|(name, want)| {
            let got = decide(&daily, &state(name));
            (got != want).then(|| format!("{name}: took {got:?}, not {want:?}"))
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    // every state on disk is in the table
    let mut on_disk: Vec<String> = std::fs::read_dir(root().join(FIXTURES))
        .expect("the fixtures")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    on_disk.sort();
    let mut named: Vec<String> = table().into_iter().map(|(n, _)| n.to_owned()).collect();
    named.sort();
    assert_eq!(on_disk, named);
}

/// The decision's three guards against a fault read as a finding: `(what, old, new)`. A config
/// cargo-deny could not read (state (c): `error[unexpected-keys]` and an `[ERROR]` line) is
/// kept from the findings twice, by the advisory kinds and by the fault check, so no one
/// plant restores the reading this fold removed, and the two pairs that keep the kinds wide
/// do; the third pair leaves (c) with no advisory's kind and so not judged.
const GUARDS: [(&str, &str, &str); 3] = [
    (
        "the advisory kinds widened to any `error[...]`",
        "          advisory='^error\\[(vulnerability|notice|unmaintained|unsound|yanked)\\]'\n",
        "          advisory='^error\\[[a-z-]+\\]'\n",
    ),
    (
        "the fault check dropped from the condition",
        "            if [[ -n \"$fault\" || -z \"$kinds\" ]]; then\n",
        "            if [[ -z \"$kinds\" ]]; then\n",
    ),
    (
        "cargo-deny's own `[ERROR]` line unread",
        " [0-9:]{8} \\[ERROR\\] ",
        " [0-9:]{8} \\[NOERROR\\] ",
    ),
];

fn plant(daily: &str, (what, old, new): (&str, &str, &str)) -> String {
    assert_eq!(
        daily.matches(old).count(),
        1,
        "`{old}` is not once in advisories.yml ({what})"
    );
    daily.replacen(old, new, 1)
}

#[test]
fn a_config_cargo_deny_cannot_read_is_never_an_advisory_finding_1034() {
    if not_here() {
        return;
    }
    let daily = read(DAILY);
    let c = state("c_unknown_advisories_key");
    let not_judged = Branch::NotJudged(NOT_JUDGED.to_owned());
    assert_eq!(decide(&daily, &c), not_judged);
    // (planted guards, whether (c) is then read as a finding)
    let cells: [(&[usize], bool); 6] = [
        (&[0], false),
        (&[1], false),
        (&[2], false),
        (&[0, 1], true),
        (&[0, 2], true),
        (&[1, 2], false),
    ];
    for (planted, finding) in cells {
        let text = planted
            .iter()
            .fold(daily.clone(), |text, &at| plant(&text, GUARDS[at]));
        let names: Vec<&str> = planted.iter().map(|&at| GUARDS[at].0).collect();
        let got = decide(&text, &c);
        assert_eq!(
            matches!(got, Branch::Finding(_)),
            finding,
            "{names:?}: (c) took {got:?}"
        );
    }
    // an advisory's finding stays one under both guards: the planted lock on three graphs
    assert_eq!(
        decide(&daily, &state("e_advisory_in_the_lock")),
        Branch::Finding(SLAB.to_owned())
    );
}
