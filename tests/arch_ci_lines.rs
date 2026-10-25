//! Beta carries everything main carries, and main nothing beta did not bear,
//! checked by CI (RELEASING.md, "The direction rule").
//!
//! The owner's word of 2026-10-25: every fix is born on `beta`, a main commit
//! is a `git cherry-pick -x` of a beta commit, and main's commits come back to
//! beta by a cherry-pick PR landed by rebase merge (both lines keep linear
//! history). A commit is on a line by sha, by patch (`git cherry`), or by a
//! `(cherry picked from commit <sha>)` link in either direction. This guard
//! reads `.github/workflows/ci.yml` and
//! `.github/workflows/sync-main-into-beta.yml` (nothing else; no network, no
//! environment) at the string level, as `arch_ci_runs_every_test.rs` reads
//! ci.yml, and refuses, naming the line it misses: a workflow that is not a
//! workflow's shape or runs an action not pinned by sha; a `main-in-beta` job
//! that is gone, runs on no PR into or push to beta, checks out a shallow
//! history, or no longer reads `git cherry` and the link; a `beta-born` job
//! that is gone, runs on no PR into main, or lost its release allowance; a
//! sync that no longer fires on main, merges, rebases or squashes, picks
//! without `-x`, rebuilds a branch holding beta's tip, falls back to main's
//! tip, keeps the checkout's credentials, cannot create its label, or opens
//! its PR anywhere but from `sync/main-into-beta` into `beta`.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

use std::fs;
use std::path::PathBuf;

const SYNC_FILE: &str = ".github/workflows/sync-main-into-beta.yml";

fn read(path: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // A Windows checkout converts the workflows to CRLF (`.gitattributes` keeps only the
    // vectors, fixtures and corpora byte for byte); the needles are written with `\n`.
    fs::read_to_string(root.join(path))
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .replace("\r\n", "\n")
}

/// The lines of the block opened by `header` at `indent` spaces: every line
/// after it up to the next line at that indent or shallower (blank lines kept).
fn block<'a>(text: &'a str, indent: usize, header: &str) -> Option<Vec<&'a str>> {
    let open = format!("{}{header}", " ".repeat(indent));
    let mut lines = text.lines().skip_while(|l| l.trim_end() != open);
    lines.next()?;
    Some(
        lines
            .take_while(|l| {
                l.trim().is_empty() || l.len() - l.trim_start().len() > indent || l.starts_with('#')
            })
            .collect(),
    )
}

/// A workflow's shape: no tab, the four top-level keys, a `runs-on` in every
/// job (a reusable call aside), and every action pinned by a 40-hex sha.
fn shape(name: &str, text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    for line in text.lines() {
        let key = line.trim().trim_start_matches("- ");
        let Some(action) = key.strip_prefix("uses: ") else {
            continue;
        };
        let sha = action
            .split_once('@')
            .map(|(_, rest)| rest.split_whitespace().next().unwrap_or(""));
        let pinned = sha.is_some_and(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()));
        if !action.starts_with("./") && !pinned {
            errors.push(format!("{name}: `{}` is not pinned by sha", line.trim()));
        }
    }
    if text.contains('\t') {
        errors.push(format!("{name}: a tab; YAML indents with spaces"));
    }
    for key in ["name:", "on:", "permissions:", "jobs:"] {
        if !text.lines().any(|l| l.starts_with(key)) {
            errors.push(format!("{name}: no top-level `{key}`"));
        }
    }
    let Some(jobs) = block(text, 0, "jobs:") else {
        return errors;
    };
    let mut job: Option<&str> = None;
    let mut runs = false;
    let close = |job: Option<&str>, runs: bool, errors: &mut Vec<String>| {
        if let Some(job) = job {
            if !runs {
                errors.push(format!("{name}: job `{job}` has no `runs-on` or `uses`"));
            }
        }
    };
    for line in jobs {
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();
        if indent == 2 && trimmed.ends_with(':') && !trimmed.starts_with('#') {
            close(job, runs, &mut errors);
            job = Some(trimmed.trim_end_matches(':'));
            runs = false;
        } else if indent == 4 && (trimmed.starts_with("runs-on:") || trimmed.starts_with("uses:")) {
            runs = true;
        }
    }
    close(job, runs, &mut errors);
    errors
}

/// The needles of a job: each present, else an error naming why it matters.
fn needles(what: &str, job: &str, list: &[(&str, &str)], errors: &mut Vec<String>) {
    for (needle, why) in list {
        if !job.contains(needle) {
            errors.push(format!("{what}: {why}; it lacks `{needle}`"));
        }
    }
}

/// The link reading both guards share: `git cherry`'s `+` lines, the trailer
/// read off the commit, the trailer looked for in the other line's log, never
/// a log piped into `grep -q` (under pipefail its writer dies of SIGPIPE).
const LINK: [(&str, &str); 4] = [
    (
        "[ \"$mark\" = \"+\" ] || continue",
        "a patch-equivalent commit (`git cherry`'s `-`) is on the line",
    ),
    (
        "s/.*(cherry picked from commit \\([0-9a-f]\\{40\\}\\)).*/\\1/p",
        "it reads the commit's cherry-pick link",
    ),
    (
        "grep -qF \"(cherry picked from commit ${sha})\" <<< \"$linked\"",
        "it reads a link naming the commit from the other line",
    ),
    (
        "missing+=(\"$sha\")",
        "it collects the commits with no link",
    ),
];

/// What the `main-in-beta` job of ci.yml must hold.
fn main_in_beta(ci: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let on = block(ci, 0, "on:").unwrap_or_default().join("\n");
    for (needle, why) in [
        (
            "push:\n    branches: [main, beta]",
            "ci.yml runs on no push to beta",
        ),
        (
            "pull_request:\n    branches: [main, beta]",
            "ci.yml runs on no PR into beta or main",
        ),
        (
            "workflow_dispatch:",
            "ci.yml cannot be started on the sync PR's branch",
        ),
    ] {
        if !on.contains(needle) {
            errors.push(format!("{why} (`on:` lacks `{needle}`)"));
        }
    }
    let Some(job) = block(ci, 2, "main-in-beta:") else {
        errors.push("ci.yml: no `main-in-beta` job".to_owned());
        return errors;
    };
    let job = job.join("\n");
    needles(
        "main-in-beta",
        &job,
        &[
            (
                "name: main-in-beta",
                "the check's context is named `main-in-beta`",
            ),
            (
                "github.event_name == 'pull_request' && github.base_ref == 'beta'",
                "it runs on every PR into beta",
            ),
            (
                "github.event_name == 'push' && github.ref == 'refs/heads/beta'",
                "it runs on every push to beta",
            ),
            (
                "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/sync/main-into-beta'",
                "it runs on the sync branch's dispatch",
            ),
            ("fetch-depth: 0", "the link reading needs the whole history"),
            (
                "persist-credentials: false",
                "the checkout keeps no credentials",
            ),
            ("set -euo pipefail", "a failed command fails the check"),
            ("git fetch --no-tags origin main", "it reads main's tip"),
            (
                "done < <(git cherry HEAD origin/main)",
                "it reads main's commits the tree lacks by patch",
            ),
            (
                "git merge-base --is-ancestor \"$src\" HEAD",
                "a main commit's beta source is on the tree",
            ),
            ("exit 1", "it fails"),
        ],
        &mut errors,
    );
    needles("main-in-beta", &job, &LINK, &mut errors);
    if job.contains("| grep -q") {
        errors.push("main-in-beta: a log piped into `grep -q` (SIGPIPE under pipefail)".to_owned());
    }
    errors
}

/// What the `beta-born` job of ci.yml must hold.
fn beta_born(ci: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(job) = block(ci, 2, "beta-born:") else {
        return vec!["ci.yml: no `beta-born` job".to_owned()];
    };
    let job = job.join("\n");
    needles(
        "beta-born",
        &job,
        &[
            (
                "name: beta-born",
                "the check's context is named `beta-born`",
            ),
            (
                "if: github.event_name == 'pull_request' && github.base_ref == 'main'",
                "it runs on every PR into main",
            ),
            ("fetch-depth: 0", "the link reading needs the whole history"),
            (
                "persist-credentials: false",
                "the checkout keeps no credentials",
            ),
            ("set -euo pipefail", "a failed command fails the check"),
            ("git fetch --no-tags origin beta", "it reads beta's tip"),
            (
                "done < <(git cherry origin/beta \"$PR_HEAD\" \"$base\")",
                "it reads the PR's commits beta lacks by patch",
            ),
            (
                "git merge-base --is-ancestor \"$src\" origin/beta",
                "a PR commit's beta source is on beta",
            ),
            (
                "case \"$file\" in Cargo.toml | CHANGELOG.md) ;; *) return 1 ;; esac",
                "a release commit touches Cargo.toml and CHANGELOG.md alone",
            ),
            (
                "^[-+](version = \"[^\"]*\"|## \\[(Unreleased|[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.]+)?)\\]( - [0-9]{4}-[0-9]{2}-[0-9]{2})?)?$",
                "a release commit changes a version and the headings alone",
            ),
            (
                "a release commit, main-born by nature",
                "the release allowance is said in the log",
            ),
            ("exit 1", "it fails"),
        ],
        &mut errors,
    );
    needles("beta-born", &job, &LINK, &mut errors);
    if job.contains("| grep -q") {
        errors.push("beta-born: a log piped into `grep -q` (SIGPIPE under pipefail)".to_owned());
    }
    errors
}

/// What sync-main-into-beta.yml must hold.
fn sync(text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let on = block(text, 0, "on:").unwrap_or_default().join("\n");
    if !on.contains("push:\n    branches: [main]") {
        errors.push("sync: it fires on no push to main".to_owned());
    }
    needles(
        "sync",
        text,
        &[
            (
                "persist-credentials: false",
                "the checkout keeps no credentials",
            ),
            ("fetch-depth: 0", "the picks need the whole history"),
            ("contents: write", "it pushes the sync branch"),
            ("pull-requests: write", "it opens the PR"),
            ("issues: write", "it creates the needs-hand label (M1)"),
            ("actions: write", "it starts ci.yml on its branch"),
            (
                "SYNC_BRANCH: sync/main-into-beta",
                "the PR's branch is sync/main-into-beta",
            ),
            (
                "done < <(git cherry \"$tip\" origin/main)",
                "it reads main's commits a tip lacks by patch, as main-in-beta does",
            ),
            (
                "git cherry-pick -x --keep-redundant-commits \"$sha\"",
                "each commit is picked with its link",
            ),
            (
                "git cherry-pick --abort",
                "a conflicting pick is aborted, the picks before it kept (M3)",
            ),
            (
                "git merge-base --is-ancestor origin/beta \"$old\"",
                "a branch holding beta's tip is picked onto, never rebuilt (M2)",
            ),
            (
                "--force-with-lease=\"$LEASE\"",
                "a branch a person pushed since the fetch is never overwritten",
            ),
            ("Land it by rebase merge", "the PR says how it lands"),
            (
                "--head \"$SYNC_BRANCH\" --base beta",
                "the PR goes into beta",
            ),
            ("gh pr edit", "a rerun updates the open PR in place"),
            (
                "sync: main into beta at ",
                "the PR's title names main's sha",
            ),
            (
                "gh label create needs-hand",
                "a conflicted pick is labelled (M1)",
            ),
            (
                "x-access-token:${GH_TOKEN}@github.com",
                "the push carries its token explicitly",
            ),
            (
                "gh workflow run ci.yml",
                "the PR's checks are started by a dispatch",
            ),
        ],
        &mut errors,
    );
    for (refused, why) in [
        ("git rebase", "the sync picks, it never rebases"),
        (
            "git merge ",
            "the sync picks, it never merges (linear history)",
        ),
        ("--no-ff", "no merge commit lands on a linear line"),
        ("--squash", "a squash drops each pick's link"),
        (
            "persist-credentials: true",
            "the checkout keeps no credentials",
        ),
        (
            "\"$SYNC_BRANCH\" origin/main",
            "the branch never falls back to main's tip (M3)",
        ),
        (
            "| grep -q",
            "a log piped into `grep -q` (SIGPIPE under pipefail)",
        ),
    ] {
        if text.contains(refused) {
            errors.push(format!("sync: `{refused}`; {why}"));
        }
    }
    errors
}

#[test]
fn both_workflows_have_a_workflows_shape() {
    let mut errors = shape("ci.yml", &read(".github/workflows/ci.yml"));
    errors.extend(shape("sync-main-into-beta.yml", &read(SYNC_FILE)));
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn main_in_beta_fails_a_beta_tree_without_a_link_to_each_main_commit() {
    let errors = main_in_beta(&read(".github/workflows/ci.yml"));
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn beta_born_fails_a_main_pr_commit_beta_did_not_bear_save_a_release() {
    let errors = beta_born(&read(".github/workflows/ci.yml"));
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn every_push_to_main_opens_a_cherry_pick_pr_into_beta() {
    let errors = sync(&read(SYNC_FILE));
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn a_ci_yml_without_a_job_its_link_or_its_allowance_is_refused() {
    let ci = read(".github/workflows/ci.yml");
    let gone = ci.replace("  main-in-beta:\n", "  main-in-beta-gone:\n");
    assert!(main_in_beta(&gone)
        .iter()
        .any(|e| e == "ci.yml: no `main-in-beta` job"));
    let sha_only = ci.replace(
        "done < <(git cherry HEAD origin/main)",
        "done < <(git rev-list HEAD..origin/main)",
    );
    assert!(main_in_beta(&sha_only)
        .iter()
        .any(|e| e.contains("git cherry HEAD origin/main")));
    let unlinked = ci.replace("<<< \"$linked\"", "<<< \"\"");
    assert!(main_in_beta(&unlinked)
        .iter()
        .any(|e| e.contains("a link naming the commit")));
    assert!(beta_born(&unlinked)
        .iter()
        .any(|e| e.contains("a link naming the commit")));
    let piped = ci.replace(
        "grep -qF \"(cherry picked from commit ${sha})\" <<< \"$linked\"",
        "git log --format=%B | grep -qF \"(cherry picked from commit ${sha})\"",
    );
    assert!(main_in_beta(&piped).iter().any(|e| e.contains("SIGPIPE")));
    let shallow = ci.replacen(
        "fetch-depth: 0",
        "fetch-depth: 1",
        ci.matches("fetch-depth: 0").count(),
    );
    assert!(main_in_beta(&shallow)
        .iter()
        .any(|e| e.contains("fetch-depth: 0")));
    assert!(beta_born(&shallow)
        .iter()
        .any(|e| e.contains("fetch-depth: 0")));
    let born_gone = ci.replace("  beta-born:\n", "  beta-born-gone:\n");
    assert_eq!(beta_born(&born_gone), vec!["ci.yml: no `beta-born` job"]);
    let no_release = ci.replace("Cargo.toml | CHANGELOG.md)", "Cargo.toml)");
    assert!(beta_born(&no_release)
        .iter()
        .any(|e| e.contains("Cargo.toml and CHANGELOG.md alone")));
    let off_main = ci.replace(
        "if: github.event_name == 'pull_request' && github.base_ref == 'main'",
        "if: github.event_name == 'pull_request' && github.base_ref == 'beta'",
    );
    assert!(beta_born(&off_main)
        .iter()
        .any(|e| e.contains("every PR into main")));
}

#[test]
fn a_sync_that_merges_rebuilds_or_drops_its_link_is_refused() {
    let text = read(SYNC_FILE);
    let merged = text.replace(
        "git cherry-pick -x --keep-redundant-commits \"$sha\"",
        "git merge --no-ff --no-edit origin/main",
    );
    let errors = sync(&merged);
    assert!(errors.iter().any(|e| e.contains("picked with its link")));
    assert!(errors.iter().any(|e| e.contains("`--no-ff`")));
    assert!(errors.iter().any(|e| e.contains("`git merge `")));
    let unlinked = text.replace("git cherry-pick -x ", "git cherry-pick ");
    assert!(sync(&unlinked)
        .iter()
        .any(|e| e.contains("picked with its link")));
    let rebuilt = text.replace("git merge-base --is-ancestor origin/beta \"$old\"", "false");
    assert!(sync(&rebuilt).iter().any(|e| e.contains("(M2)")));
    let main_tip = text.replace(
        "git checkout --quiet -B \"$SYNC_BRANCH\" origin/beta\n            if",
        "git checkout --quiet -B \"$SYNC_BRANCH\" origin/main\n            if",
    );
    assert_ne!(main_tip, text);
    assert!(sync(&main_tip)
        .iter()
        .any(|e| e.contains("main's tip (M3)")));
    let no_label = text.replace("      issues: write\n", "");
    assert!(sync(&no_label)
        .iter()
        .any(|e| e.contains("`issues: write`")));
    let off_main = text.replace("push:\n    branches: [main]", "push:\n    branches: [beta]");
    assert!(sync(&off_main)
        .iter()
        .any(|e| e == "sync: it fires on no push to main"));
}

#[test]
fn the_shape_check_names_a_job_with_no_runner_and_an_unpinned_action() {
    let text = "name: x\non:\n  push:\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n  b:\n    steps: []\n";
    assert_eq!(
        shape("x.yml", text),
        vec![
            "x.yml: `- uses: actions/checkout@v4` is not pinned by sha".to_owned(),
            "x.yml: job `b` has no `runs-on` or `uses`".to_owned(),
        ]
    );
}
