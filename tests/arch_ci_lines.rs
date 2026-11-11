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
//!
//! The bundled gates (CI speed round 1, cut 2; `docs/lanes/ci-speed-2.md`): `lint` and
//! `checks` each carry their gates as steps of one runner, one setup each, and are refused
//! when a gate is gone, would stop running after an earlier gate failed, prints no
//! `PASS`/`FAIL` line of its own, or is missing from the last step that names every gate
//! that did not pass; a job with a matrix or a second cache restore is refused too.
//!
//! The Release page (the design reads of 2026-11-11, D7 and D9; RELEASING.md step 5):
//! `release.yml` refuses a tag whose `CHANGELOG.md` has no section before it publishes,
//! makes the page in a `page` job after `Publish to crates.io` (notes from
//! `front_pages.py notes` with this run's id, flags from `front_pages.py flags`), holds
//! `contents: write` in that job alone, and runs the reconciler after it;
//! `front-pages.yml` runs the reconciler on a dispatch and nothing else (no schedule).
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

/// The gates of each bundled job: (job, [(step id, gate)]). The gate is the line's word, the
/// context each step replaced.
const BUNDLES: &[(&str, &[(&str, &str)])] = &[
    (
        "lint",
        &[
            ("fmt", "Rustfmt"),
            ("clippy", "Clippy"),
            ("deny", "deny"),
            ("ratchet", "ratchet"),
        ],
    ),
    (
        "checks",
        &[
            ("mutants-entries", "mutants-entries"),
            // the Release page generator's and the reconciler's tests (front_pages.py), run
            // at every pull request so release.yml's page job never meets them broken
            ("front-pages", "front-pages"),
            ("vectors", "vectors"),
            ("fixtures", "fixtures"),
            ("secrets", "secrets"),
            ("docs", "Documentation"),
            ("wasm32", "wasm32 (combined)"),
        ],
    ),
];

/// The steps of a job: each from its `- ` line at six spaces to the next.
fn steps(job: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in job {
        if line.starts_with("      - ") {
            out.push(String::new());
        }
        if let Some(step) = out.last_mut() {
            step.push_str(line);
            step.push('\n');
        }
    }
    out
}

/// What a bundled job of ci.yml must hold: every gate a step that runs after an earlier
/// failure and prints its own line, one cache restore, no matrix, and a last step that runs
/// whatever failed and names every gate whose step did not succeed.
fn bundle(ci: &str, id: &str, gates: &[(&str, &str)]) -> Vec<String> {
    let Some(job) = block(ci, 2, &format!("{id}:")) else {
        return vec![format!("ci.yml: no `{id}` job")];
    };
    let mut errors = Vec::new();
    if job.iter().any(|l| l.trim_start().starts_with("strategy:")) {
        errors.push(format!("{id}: a matrix; the gates are steps of one runner"));
    }
    let caches = job
        .iter()
        .filter(|l| l.contains("uses: Swatinem/rust-cache@"))
        .count();
    if caches != 1 {
        errors.push(format!("{id}: {caches} cache restores, not one"));
    }
    let steps = steps(&job);
    let gated: Vec<&str> = steps
        .iter()
        .filter_map(|s| {
            s.lines()
                .find_map(|l| l.trim().strip_prefix("id: "))
                // the lockfile step and the docs-only plan (#668) are no gates
                .filter(|i| *i != "ready" && *i != "plan")
        })
        .collect();
    for gate_id in &gated {
        if !gates.iter().any(|(g, _)| g == gate_id) {
            errors.push(format!(
                "{id}: step `{gate_id}` is no gate of the verdict list"
            ));
        }
    }
    for (step_id, gate) in gates {
        let Some(step) = steps
            .iter()
            .find(|s| s.lines().any(|l| l.trim() == format!("id: {step_id}")))
        else {
            errors.push(format!("{id}: no step `{step_id}` for the gate {gate}"));
            continue;
        };
        // `secrets` also runs on a docs-only change, whose `ready` is skipped (#668)
        let runs_after = step
            .contains("        if: ${{ !cancelled() && steps.ready.outcome == 'success' }}\n")
            || (*step_id == "secrets"
                && step.contains("        if: ${{ !cancelled() && (steps.ready.outcome == 'success' || steps.plan.outputs.docs_only == 'true') }}\n"));
        if !runs_after {
            errors.push(format!(
                "{id}: `{step_id}` does not run after an earlier gate failed (`!cancelled()`)"
            ));
        }
        let line = format!(
            "trap 'if [ $? -eq 0 ]; then echo \"PASS {gate}\"; else echo \"FAIL {gate}\"; fi' EXIT"
        );
        if !step.contains(&line) {
            errors.push(format!(
                "{id}: `{step_id}` prints no PASS/FAIL line of its own"
            ));
        }
    }
    let Some(last) = steps.last() else {
        errors.push(format!("{id}: no steps"));
        return errors;
    };
    if !last.contains("- name: Every gate passed\n        if: ${{ !cancelled() }}\n") {
        errors.push(format!(
            "{id}: the last step is not `Every gate passed` on `!cancelled()`"
        ));
    }
    for (step_id, gate) in gates {
        if !last.contains(&format!("${{{{ steps.{step_id}.outcome }}}} {gate}\n")) {
            errors.push(format!("{id}: the last step does not judge `{gate}`"));
        }
    }
    for needle in ["echo \"FAIL $gate", "failed+=(\"$gate\")", "exit 1"] {
        if !last.contains(needle) {
            errors.push(format!(
                "{id}: the last step does not fail naming the gate (`{needle}`)"
            ));
        }
    }
    errors
}

#[test]
fn the_bundled_gates_each_run_and_report_and_the_last_step_names_every_failure() {
    let ci = read(".github/workflows/ci.yml");
    let mut errors = Vec::new();
    for (id, gates) in BUNDLES {
        errors.extend(bundle(&ci, id, gates));
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    // the contexts a bundle replaced are gone as jobs: one runner per bundle, not two
    for gone in [
        "\n  clippy:\n",
        "\n  fmt:\n",
        "\n  deny:\n",
        "\n  ratchet:\n",
        "\n  vectors:\n",
        "\n  fixtures:\n",
        "\n  secrets:\n",
        "\n  docs:\n",
        "\n  wasm32:\n",
    ] {
        assert!(!ci.contains(gone), "a bundled gate is a job again: {gone}");
    }
}

#[test]
fn a_bundle_with_a_gate_stopped_unreported_or_unjudged_is_refused() {
    let ci = read(".github/workflows/ci.yml");
    let (_, lint) = BUNDLES[0];
    let (_, checks) = BUNDLES[1];
    let stopping = ci.replacen(
        "        id: deny\n        if: ${{ !cancelled() && steps.ready.outcome == 'success' }}\n",
        "        id: deny\n",
        1,
    );
    assert_eq!(
        bundle(&stopping, "lint", lint),
        ["lint: `deny` does not run after an earlier gate failed (`!cancelled()`)"]
    );
    let silent = ci.replacen(
        "          trap 'if [ $? -eq 0 ]; then echo \"PASS fixtures\"; else echo \"FAIL fixtures\"; fi' EXIT\n",
        "",
        1,
    );
    assert_eq!(
        bundle(&silent, "checks", checks),
        ["checks: `fixtures` prints no PASS/FAIL line of its own"]
    );
    let unjudged = ci.replacen(
        "            ${{ steps.docs.outcome }} Documentation\n",
        "",
        1,
    );
    assert_eq!(
        bundle(&unjudged, "checks", checks),
        ["checks: the last step does not judge `Documentation`"]
    );
    let gone = ci.replacen("        id: ratchet\n", "        id: ratchet-gone\n", 1);
    assert_eq!(
        bundle(&gone, "lint", lint),
        [
            "lint: step `ratchet-gone` is no gate of the verdict list",
            "lint: no step `ratchet` for the gate ratchet",
        ]
    );
    let twice = ci.replacen(
        "      - name: Cache the checks' builds\n",
        "      - uses: Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0 # v2.9.3\n      - name: Cache the checks' builds\n",
        1,
    );
    assert_eq!(
        bundle(&twice, "checks", checks),
        ["checks: 2 cache restores, not one"]
    );
    let lenient = ci.replacen(
        "      - name: Every gate passed\n        if: ${{ !cancelled() }}\n",
        "      - name: Every gate passed\n",
        1,
    );
    assert_eq!(
        bundle(&lenient, "lint", lint),
        ["lint: the last step is not `Every gate passed` on `!cancelled()`"]
    );
}

/// The cargo-mutants version a workflow names in `CARGO_MUTANTS_VERSION: '<v>'`.
fn mutants_version(text: &str) -> Option<&str> {
    let at = text.find("CARGO_MUTANTS_VERSION: '")? + "CARGO_MUTANTS_VERSION: '".len();
    text[at..].split('\'').next()
}

/// #663: the equivalence entries' check runs in the `checks` gate and in the nightly's pin
/// job before the plan (so before any shard), both at the nightly's cargo-mutants version.
fn mutants_entries(ci: &str, nightly: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let check = "python3 .github/scripts/mutants_entries.py\n";
    let gate = block(ci, 2, "checks:")
        .map(|j| steps(&j))
        .unwrap_or_default();
    if !gate
        .iter()
        .any(|s| s.contains("id: mutants-entries\n") && s.contains(check))
    {
        errors.push("checks: the mutants-entries gate does not run mutants_entries.py".to_owned());
    }
    let pin = block(nightly, 2, "source:")
        .map(|j| steps(&j))
        .unwrap_or_default();
    let at = pin.iter().position(|s| s.contains(check));
    let plan = pin.iter().position(|s| s.contains("id: plan\n"));
    if !matches!((at, plan), (Some(a), Some(p)) if a < p) {
        errors.push("nightly: the pin job does not check the entries before its plan".to_owned());
    }
    if pin.iter().any(|s| s.contains(check) && s.contains("--fix"))
        || ci.contains("mutants_entries.py --fix")
    {
        errors
            .push("a workflow rewrites the entries (`--fix` is the captain's, by hand)".to_owned());
    }
    match (mutants_version(ci), mutants_version(nightly)) {
        (Some(c), Some(n)) if c == n => {}
        (c, n) => errors.push(format!(
            "cargo-mutants {c:?} in ci.yml, {n:?} in the nightly"
        )),
    }
    errors
}

#[test]
fn every_mutants_entry_is_checked_in_checks_and_the_pin_job_at_one_version_663() {
    let ci = read(".github/workflows/ci.yml");
    let nightly = read(".github/workflows/nightly.yml");
    assert_eq!(mutants_entries(&ci, &nightly), Vec::<String>::new());
    let moved = ci.replacen("CARGO_MUTANTS_VERSION: '", "CARGO_MUTANTS_VERSION: '0.", 1);
    assert_eq!(mutants_entries(&moved, &nightly).len(), 1);
    let unchecked = nightly.replacen(
        "PATH=\"$RUNNER_TEMP/tools/bin:$PATH\" python3 .github/scripts/mutants_entries.py\n",
        "\n",
        1,
    );
    assert_eq!(
        mutants_entries(&ci, &unchecked),
        ["nightly: the pin job does not check the entries before its plan"]
    );
    let fixing = ci.replacen(
        "python3 .github/scripts/mutants_entries.py\n",
        "python3 .github/scripts/mutants_entries.py --fix\n",
        1,
    );
    assert_eq!(
        mutants_entries(&fixing, &nightly),
        [
            "checks: the mutants-entries gate does not run mutants_entries.py",
            "a workflow rewrites the entries (`--fix` is the captain's, by hand)",
        ]
    );
}

/// What release.yml and front-pages.yml must hold for the Release page and the reconciler.
fn release_pages(release: &str, dispatch: &str) -> Vec<String> {
    let mut errors = shape("release.yml", release);
    errors.extend(shape("front-pages.yml", dispatch));
    let job = |name: &str| {
        block(release, 2, &format!("{name}:"))
            .unwrap_or_default()
            .join("\n")
    };
    let version = job("version");
    if !version.contains("- name: The tag's changelog has its section")
        || !version.contains(r#"grep -qE "^## \[${version//./\\.}\]( |$)" CHANGELOG.md"#)
    {
        errors.push("release.yml: the version job does not refuse a tag without its changelog section before the publish".to_owned());
    }
    let page = job("page");
    if page.is_empty() {
        errors.push("release.yml: no `page` job".to_owned());
    }
    for (needle, why) in [
        (
            "needs: publish",
            "the page is made after the crate is published",
        ),
        ("contents: write", "it creates the release"),
        (
            "test_front_pages.py",
            "the generator's tests before it runs",
        ),
        (
            r#"front_pages.py notes "$GITHUB_REF_NAME" --run "$GITHUB_RUN_ID""#,
            "the notes from the tag and this run",
        ),
        (
            r#"front_pages.py flags "$GITHUB_REF_NAME""#,
            "prerelease and Latest from the version",
        ),
        (
            r#"gh release create "$GITHUB_REF_NAME" --verify-tag"#,
            "the page of the pushed tag alone",
        ),
    ] {
        if !page.contains(needle) {
            errors.push(format!("release.yml page: no `{needle}` ({why})"));
        }
    }
    let writers = release.matches("contents: write").count();
    if writers != 1 {
        errors.push(format!(
            "release.yml: `contents: write` in {writers} places, not the page job's alone"
        ));
    }
    let agree = job("front-pages");
    for (needle, why) in [
        ("needs: page", "the reconciler reads the page just made"),
        ("front_pages.py check", "the reconciler runs"),
    ] {
        if !agree.contains(needle) {
            errors.push(format!("release.yml front-pages: no `{needle}` ({why})"));
        }
    }
    let on = block(dispatch, 0, "on:").unwrap_or_default().join("\n");
    if !on.contains("workflow_dispatch:") {
        errors.push("front-pages.yml: not dispatchable".to_owned());
    }
    for trigger in ["schedule:", "push:", "pull_request", "workflow_run:"] {
        if on.contains(trigger) {
            errors.push(format!(
                "front-pages.yml: fires on `{trigger}`; the reconciler runs on a dispatch alone"
            ));
        }
    }
    if !dispatch.contains("front_pages.py check") {
        errors.push("front-pages.yml: does not run the reconciler".to_owned());
    }
    errors
}

#[test]
fn the_release_makes_its_page_after_the_publish_and_the_reconciler_runs_on_dispatch_alone() {
    let release = read(".github/workflows/release.yml");
    let dispatch = read(".github/workflows/front-pages.yml");
    let errors = release_pages(&release, &dispatch);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn a_release_page_made_early_with_write_elsewhere_or_a_scheduled_reconciler_is_refused() {
    let release = read(".github/workflows/release.yml");
    let dispatch = read(".github/workflows/front-pages.yml");
    let unchecked = release.replacen(
        "      - name: The tag's changelog has its section\n",
        "      - name: renamed\n",
        1,
    );
    assert_eq!(
        release_pages(&unchecked, &dispatch),
        ["release.yml: the version job does not refuse a tag without its changelog section before the publish"]
    );
    let early = release.replacen(
        "    needs: publish\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n",
        "    needs: ci\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n",
        1,
    );
    assert_eq!(
        release_pages(&early, &dispatch),
        ["release.yml page: no `needs: publish` (the page is made after the crate is published)"]
    );
    let wide = release.replacen(
        "permissions:\n  contents: read\n",
        "permissions:\n  contents: write\n",
        1,
    );
    assert_eq!(
        release_pages(&wide, &dispatch),
        ["release.yml: `contents: write` in 2 places, not the page job's alone"]
    );
    let back_patch = release.replacen(
        r#"front_pages.py flags "$GITHUB_REF_NAME""#,
        "echo --latest",
        1,
    );
    assert_eq!(
        release_pages(&back_patch, &dispatch),
        [
            r#"release.yml page: no `front_pages.py flags "$GITHUB_REF_NAME"` (prerelease and Latest from the version)"#
        ]
    );
    let scheduled = dispatch.replacen(
        "on:\n  workflow_dispatch:\n",
        "on:\n  schedule:\n    - cron: '0 6 * * *'\n  workflow_dispatch:\n",
        1,
    );
    assert_eq!(
        release_pages(&release, &scheduled),
        ["front-pages.yml: fires on `schedule:`; the reconciler runs on a dispatch alone"]
    );
}
