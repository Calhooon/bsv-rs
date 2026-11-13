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
//!
//! The sync's dispatch of stage R (#97): `SYNC_STAGE_R` holds its steps byte for byte, and
//! `SYNC_FILE_DIGEST` holds `sync-main-into-beta.yml` whole, so a second definition of a variable
//! the dispatch reads, in any spelling (a flow mapping, a multiline write to `$GITHUB_ENV`, a YAML
//! escape in a key), moves the file and fails; the scan of definitions
//! (`every_variable_the_stage_r_dispatch_reads_has_its_one_definition_97`) stays beside it as a
//! readable second check and does not claim every spelling. The bound: what holds the sync's
//! dispatch is the pinned step's text and the digest of the whole workflow; what neither sees is a
//! change that edits the workflow and its digest in the same pull request (a reviewer's matter,
//! visible in the diff), and a value GitHub keeps outside the file (an organization or repository
//! variable, which reaches a job only through a `${{ vars.NAME }}` the file would carry, and of
//! which the repository and its organization held none on 2026-11-13).
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

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
    errors.extend(sync_stage_r(text));
    errors.extend(sync_stage_r_reads(text));
    errors.extend(sync_stage_r_judge(text));
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

/// The sync's dispatch of stage R of the node oracle's judge (#97), byte for byte from its
/// comment to the job's end: the step that starts ci.yml's checks on the PR's branch, then this
/// one, the last of the job. Its `--ref`, its `if:` and its place are held by the bytes, as the
/// `sibling` job's step is held in `arch_ci_pr_runs_the_required_set.rs`. Since fix-97c the step
/// also waits for the run its dispatch answered and dispatches the judge on main with its id: a
/// run the `GITHUB_TOKEN` starts raises no `workflow_run` (witness 11, run 43476255821, judged by
/// no event), so without it a sync pull request never earns `sibling-judge`.
const SYNC_STAGE_R: &str = r#"      - name: Start the PR's CI
        if: steps.pick.outputs.push == 'true'
        env:
          GH_TOKEN: ${{ github.token }}
        run: gh workflow run ci.yml --repo "$GITHUB_REPOSITORY" --ref "$SYNC_BRANCH"

      # stage R of the node oracle's judge (#97) on the PR's branch, in a step of its own after
      # ci.yml's: a GITHUB_TOKEN push starts no run, and a refused dispatch here never loses ci.yml's.
      # A run this token starts starts no run that waits for its end (a dispatch is the one event the
      # token may raise), so the trampoline never hears of it: the step takes the run's id from the dispatch's
      # own answer (no other run can share it), waits for that run to complete and dispatches the
      # judge on main with the id. It holds no key and judges nothing; a refused dispatch, or a run
      # not completed in 40 minutes, fails the job where a person sees it.
      - name: Start the PR's stage R and its judge
        if: steps.pick.outputs.push == 'true'
        timeout-minutes: 45
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -euo pipefail
          run="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/actions/workflows/sibling-run.yml/dispatches" \
            -f ref="$SYNC_BRANCH" -F return_run_details=true --jq '.run_url | split("/") | last')"
          if ! [[ "$run" =~ ^[1-9][0-9]{0,19}$ ]]; then
            echo "::error::the dispatch of stage R on ${SYNC_BRANCH} answered no run id"
            exit 1
          fi
          echo "stage R run ${run} on ${SYNC_BRANCH}"
          status=""
          for _ in $(seq 1 160); do
            status="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${run}" --jq '.status')"
            if [ "$status" = completed ]; then break; fi
            sleep 15
          done
          if [ "$status" != completed ]; then
            echo "::error::stage R run ${run} is ${status} after 40 minutes; once it completes: gh workflow run sibling-judge.yml --repo ${GITHUB_REPOSITORY} --ref main -f run_id=${run}"
            exit 1
          fi
          gh workflow run sibling-judge.yml --repo "$GITHUB_REPOSITORY" --ref main -f run_id="$run"
"#;

/// The stage R dispatch of the sync (#97): named once, and the file's tail from ci.yml's dispatch
/// to its end is `SYNC_STAGE_R`, so the step is held whole, after ci.yml's, the job's last.
fn sync_stage_r(text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let named = text.matches("sibling-run.yml").count();
    if named != 1 {
        errors.push(format!(
            "sync: `sibling-run.yml` named {named} times; the stage R dispatch (#97) names it once"
        ));
    }
    let head = "      - name: Start the PR's CI\n";
    match text.find(head) {
        None => errors.push(
            "sync: no step `Start the PR's CI`, which the stage R dispatch (#97) follows"
                .to_owned(),
        ),
        Some(at) => {
            let tail = text[at..].trim_end();
            if tail != SYNC_STAGE_R.trim_end() {
                let found = tail
                    .lines()
                    .zip(SYNC_STAGE_R.lines())
                    .position(|(a, b)| a != b)
                    .unwrap_or_else(|| tail.lines().count().min(SYNC_STAGE_R.lines().count()));
                errors.push(format!(
                    "sync: the stage R dispatch (#97) is not `SYNC_STAGE_R` byte for byte after ci.yml's step to the job's end; line {} of the pin is `{}`, found `{}`",
                    found + 1,
                    SYNC_STAGE_R.lines().nth(found).unwrap_or("<end>"),
                    tail.lines().nth(found).unwrap_or("<end>"),
                ));
            }
        }
    }
    errors
}

/// Where a variable `SYNC_STAGE_R` reads is defined: the pinned bytes hold the steps, not what
/// their variables hold, so each is held here too (the re-read of PR #931's fold: a job-level
/// `SYNC_BRANCH: beta` sent the dispatch to beta with every pinned byte standing).
#[derive(Clone, Copy)]
enum Definition {
    /// Defined once, in the workflow's top-level `env:`, as this value.
    Workflow(&'static str),
    /// Defined only in a step's own `env:`, always as this value.
    Steps(&'static str),
    /// Never defined in the file: the runner's own.
    Runner,
}

/// Every variable the pinned dispatch steps read, with where it is defined; the test
/// `every_variable_the_stage_r_dispatch_reads_has_its_one_definition_97` holds this list equal
/// to what `SYNC_STAGE_R`'s `run:` lines read, so a variable added to the pin needs its row.
const SYNC_STAGE_R_READS: &[(&str, Definition)] = &[
    ("GH_TOKEN", Definition::Steps("${{ github.token }}")),
    ("GITHUB_REPOSITORY", Definition::Runner),
    ("SYNC_BRANCH", Definition::Workflow("sync/main-into-beta")),
];

/// A text's shell lines: each `run:` line, and every line of a `run: |` block (the lines below it
/// indented deeper than the key).
fn run_lines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut block: Option<usize> = None;
    for line in text.lines() {
        let indent = line.len() - line.trim_start().len();
        if let Some(key) = block {
            if line.trim().is_empty() || indent > key {
                out.push(line);
                continue;
            }
            block = None;
        }
        if line.trim_start().starts_with("run:") {
            out.push(line);
            if line.trim_end().ends_with('|') {
                block = Some(indent);
            }
        }
    }
    out
}

/// The variables a text's steps read: those its `run:` lines expand (`$NAME`, `${NAME}`) and
/// those its steps' `env:` hands their commands (`gh` reads `GH_TOKEN` unexpanded); upper case,
/// in order.
fn variables_read(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in text.lines() {
        if let Some((key, _)) = line.trim().split_once(": ") {
            let upper = !key.is_empty()
                && key
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
            if upper && !found.iter().any(|f| f == key) {
                found.push(key.to_owned());
            }
        }
    }
    for line in run_lines(text) {
        let bytes = line.as_bytes();
        for (at, _) in line.match_indices('$') {
            let start = at + 1 + usize::from(bytes.get(at + 1) == Some(&b'{'));
            let name: String = line[start..]
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                .collect();
            if !name.is_empty() && !found.contains(&name) {
                found.push(name);
            }
        }
    }
    found
}

/// Every line of `text` that defines `name`: the name as a word (not after `$`, `{` or a word
/// character), a quote at most after it, then `:` (a YAML key, a flow mapping's included) or a
/// lone `=` (a shell assignment, an `export`, a `$GITHUB_ENV` write); one-based line numbers.
fn definitions<'a>(text: &'a str, name: &str) -> Vec<(usize, &'a str)> {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            line.match_indices(name).any(|(at, _)| {
                let before = line[..at].chars().next_back();
                if before.is_some_and(|c| word(c) || c == '$' || c == '{') {
                    return false;
                }
                let rest = &line[at + name.len()..];
                if rest.chars().next().is_some_and(word) {
                    return false;
                }
                let rest = rest.trim_start_matches(['"', '\'']).trim_start();
                rest.starts_with(':') || (rest.starts_with('=') && !rest.starts_with("=="))
            })
        })
        .map(|(n, line)| (n + 1, line))
        .collect()
}

/// The nearest line above line `n` (one-based) indented less than `indent`, comments and blank
/// lines aside.
fn parent_of(text: &str, n: usize, indent: usize) -> Option<&str> {
    text.lines()
        .take(n - 1)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .find(|l| {
            !l.trim().is_empty()
                && !l.trim_start().starts_with('#')
                && l.len() - l.trim_start().len() < indent
        })
}

/// Each variable the stage R dispatch reads is defined where `SYNC_STAGE_R_READS` says, and
/// nowhere else.
fn sync_stage_r_reads(text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    for &(name, defined) in SYNC_STAGE_R_READS {
        let found = definitions(text, name);
        let lines = || {
            found
                .iter()
                .map(|(n, l)| format!("{n} `{}`", l.trim()))
                .collect::<Vec<_>>()
                .join(", ")
        };
        match defined {
            Definition::Workflow(value) => {
                let want = format!("  {name}: {value}");
                let placed = found.len() == 1
                    && found[0].1 == want
                    && parent_of(text, found[0].0, 2) == Some("env:");
                if !placed {
                    errors.push(format!(
                        "sync: `{name}`, which the stage R dispatch (#97) reads, is defined {} times ({}); it is defined once, in the workflow's top-level `env:`, as `{}`",
                        found.len(),
                        lines(),
                        want.trim()
                    ));
                }
            }
            Definition::Steps(value) => {
                let want = format!("          {name}: {value}");
                let stray: Vec<_> = found
                    .iter()
                    .filter(|(n, l)| *l != want || parent_of(text, *n, 10) != Some("        env:"))
                    .map(|(n, l)| format!("{n} `{}`", l.trim()))
                    .collect();
                if !stray.is_empty() {
                    errors.push(format!(
                        "sync: `{name}`, which the stage R dispatch (#97) reads, is defined outside a step's `env:` or as another value ({}); it is defined in a step's own `env:` alone, as `{}`",
                        stray.join(", "),
                        want.trim()
                    ));
                }
            }
            Definition::Runner => {
                if !found.is_empty() {
                    errors.push(format!(
                        "sync: `{name}`, which the stage R dispatch (#97) reads, is defined ({}); it is the runner's own, defined nowhere in the file",
                        lines()
                    ));
                }
            }
        }
    }
    let mut configured: Vec<&str> = Vec::new();
    for (at, _) in text.match_indices("GH_") {
        let name_len = text[at..]
            .find(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
            .unwrap_or(text.len() - at);
        let name = &text[at..at + name_len];
        if name != "GH_TOKEN" && !configured.contains(&name) {
            configured.push(name);
        }
    }
    for name in configured {
        let found = definitions(text, name);
        if !found.is_empty() {
            errors.push(format!(
                "sync: `{name}` is defined ({}); `gh`, which the stage R dispatch (#97) runs, reads its `GH_*` settings unnamed, so none but `GH_TOKEN` is defined in the file",
                found
                    .iter()
                    .map(|(n, l)| format!("{n} `{}`", l.trim()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    errors
}

/// FNV-1a (`arch_support::fnv`) of `sync-main-into-beta.yml`'s whole text, line endings
/// normalized (#97's third fold, the form #819 pins its macro file by). Whoever changes the
/// workflow deliberately reads the change, then sets this to the digest the failure prints, in
/// the same diff.
const SYNC_FILE_DIGEST: u64 = 0xac0e_61cb_3cb9_3d05;

/// The sync workflow's text moved from its digest.
fn sync_digest_refusals(text: &str) -> Vec<String> {
    let digest = arch_support::fnv(text);
    if digest == SYNC_FILE_DIGEST {
        return Vec::new();
    }
    vec![format!(
        "{SYNC_FILE}: its text moved (digest {digest:#018x}, pinned {SYNC_FILE_DIGEST:#018x}): the stage R dispatch (#97) reads variables the workflow defines; read the change, then move SYNC_FILE_DIGEST in the same diff"
    )]
}

/// The sync workflow pinned whole (#97's third fold): the second re-read's two plants, which
/// passed the scan of definitions (a flow mapping with no space after its brace, a multiline
/// `$GITHUB_ENV` write), its escape row (a YAML escape in a quoted key) and an `env:` on the job
/// with a value the dispatch does not read, each refused by the digest's message.
#[test]
fn the_sync_workflow_is_pinned_whole_by_its_digest_97() {
    let text = read(SYNC_FILE);
    assert!(
        sync_digest_refusals(&text).is_empty(),
        "{:?}",
        sync_digest_refusals(&text)
    );
    let job = "    runs-on: ubuntu-latest\n";
    let pick = "      - name: Cherry-pick main's commits onto beta\n        id: pick\n        run: |\n          set -euo pipefail\n";
    assert_eq!(text.matches(job).count(), 1);
    assert_eq!(text.matches(pick).count(), 1);
    let plants: Vec<(&str, String)> = vec![
        (
            "a job-level flow mapping with no space",
            text.replace(job, &format!("{job}    env: {{SYNC_BRANCH: beta}}\n")),
        ),
        (
            "a multiline $GITHUB_ENV write",
            text.replace(
                pick,
                &format!(
                    "{pick}          {{ echo 'SYNC_BRANCH<<EOF'; echo beta; echo EOF; }} >> \"$GITHUB_ENV\"\n"
                ),
            ),
        ),
        (
            "a YAML escape in a quoted job-level key",
            text.replace(
                job,
                &format!("{job}    env:\n      \"SYNC_BRAN\\x43H\": beta\n"),
            ),
        ),
        (
            "a job-level proxy",
            text.replace(
                job,
                &format!("{job}    env:\n      HTTPS_PROXY: http://example.invalid:8080\n"),
            ),
        ),
        ("a comment added", format!("{text}# a comment\n")),
    ];
    for (what, planted) in plants {
        assert_ne!(planted, text, "{what}: the plant changed nothing");
        let errors = sync_digest_refusals(&planted);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("its text moved") && e.contains("SYNC_FILE_DIGEST")),
            "{what}: {errors:?}"
        );
    }
}

#[test]
fn both_workflows_have_a_workflows_shape() {
    let mut errors = shape("ci.yml", &read(".github/workflows/ci.yml"));
    errors.extend(shape("sync-main-into-beta.yml", &read(SYNC_FILE)));
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// The node oracle's two workflows (#97) keep a workflow's shape on beta: stage R, which beta
/// alone carries, and the trampoline, which main takes by pick (main carries no copy of this test;
/// its file is held there by the judge's comparison of the file it runs with beta's, by the
/// rehearsal of each pick and by `docs.yml` before each tag).
#[test]
fn the_judges_two_workflows_have_a_workflows_shape_97() {
    let mut errors = shape(
        "sibling-run.yml",
        &read(".github/workflows/sibling-run.yml"),
    );
    errors.extend(shape(
        "sibling-judge.yml",
        &read(".github/workflows/sibling-judge.yml"),
    ));
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    let judge = read(".github/workflows/sibling-judge.yml");
    let unpinned = judge.replacen(
        "actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510 # v3.3.0",
        "actions/create-github-app-token@v3",
        1,
    );
    assert_ne!(
        unpinned, judge,
        "the token step's pin is where the plant goes"
    );
    assert_eq!(
        shape("sibling-judge.yml", &unpinned),
        ["sibling-judge.yml: `uses: actions/create-github-app-token@v3` is not pinned by sha"]
    );
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

/// The strength read of PR #931's three plants on the stage R dispatch, each refused by name.
#[test]
fn a_sync_stage_r_dispatch_retargeted_unconditioned_or_moved_is_refused_97() {
    let text = read(SYNC_FILE);
    assert!(sync_stage_r(&text).is_empty());
    let dispatch = "-f ref=\"$SYNC_BRANCH\" -F return_run_details=true";
    let retargeted = text.replace(dispatch, "-f ref=beta -F return_run_details=true");
    assert_ne!(retargeted, text);
    assert!(
        sync(&retargeted)
            .iter()
            .any(|e| e.contains("not `SYNC_STAGE_R` byte for byte") && e.contains("-f ref=beta")),
        "{:?}",
        sync(&retargeted)
    );
    let step = "      - name: Start the PR's stage R and its judge\n        if: steps.pick.outputs.push == 'true'\n";
    let unconditioned = text.replace(step, "      - name: Start the PR's stage R and its judge\n");
    assert_ne!(unconditioned, text);
    assert!(
        sync(&unconditioned)
            .iter()
            .any(|e| e.contains("not `SYNC_STAGE_R` byte for byte")
                && e.contains("found `        timeout-minutes: 45`")),
        "{:?}",
        sync(&unconditioned)
    );
    let at = text.find("      - name: Start the PR's CI\n").unwrap();
    let stage_r_at = text
        .find("      # stage R of the node oracle's judge (#97) on the PR's branch")
        .unwrap();
    let ci_step = &text[at..stage_r_at];
    let stage_r_step = &text[stage_r_at..];
    let moved = format!(
        "{}{}\n{}",
        &text[..at],
        stage_r_step.trim_end(),
        ci_step.trim_end()
    ) + "\n";
    assert_ne!(moved, text);
    assert!(
        sync(&moved)
            .iter()
            .any(|e| e.contains("not `SYNC_STAGE_R` byte for byte") && e.contains("found `<end>`")),
        "{:?}",
        sync(&moved)
    );
}

/// The sync's stage R step earns its pull request a check (fix-97c): the run is the one the
/// dispatch answered (`return_run_details`, never a listing a second run can share), the wait is
/// bounded and its failure fails the job, and the judge is dispatched on main with that run's id;
/// the job holds no key. Each rule refused by name on a plant, beside the pin's bytes.
fn sync_stage_r_judge(text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(at) = text.find("      - name: Start the PR's stage R and its judge\n") else {
        return vec!["sync: no step `Start the PR's stage R and its judge` (fix-97c)".to_owned()];
    };
    let step = &text[at..];
    let rules: [(&str, bool, &str); 8] = [
        ("set -euo pipefail", true, "the step stops at its first failing command"),
        (
            "-F return_run_details=true --jq '.run_url | split(\"/\") | last')\"",
            true,
            "the run is the one the dispatch answered, by its id",
        ),
        (
            "[[ \"$run\" =~ ^[1-9][0-9]{0,19}$ ]]",
            true,
            "an answer that is no run id fails the job",
        ),
        (
            "gh workflow run sibling-judge.yml --repo \"$GITHUB_REPOSITORY\" --ref main -f run_id=\"$run\"",
            true,
            "the judge is dispatched on main with the answered run's id",
        ),
        ("timeout-minutes: 45", true, "the step is bounded"),
        ("gh run list", false, "no run is found by a listing a second run can share"),
        ("|| true", false, "no failure is absorbed"),
        ("continue-on-error", false, "no failure is absorbed"),
    ];
    for (needle, wanted, why) in rules {
        if step.contains(needle) != wanted {
            errors.push(format!(
                "sync: the stage R step {} `{needle}`: {why} (fix-97c)",
                if wanted { "lacks" } else { "carries" }
            ));
        }
    }
    if text.contains(concat!("SIBLING_JUDGE", "_KEY")) || text.contains("create-github-app-token") {
        errors.push(
            "sync: the workflow names the judge's key: the sync judges nothing (fix-97c)"
                .to_owned(),
        );
    }
    errors
}

#[test]
fn the_sync_stage_r_step_waits_for_its_own_run_and_dispatches_its_judge_97c() {
    let text = read(SYNC_FILE);
    assert!(
        sync_stage_r_judge(&text).is_empty(),
        "{:?}",
        sync_stage_r_judge(&text)
    );
    let latest = "          run=\"$(gh run list --repo \"$GITHUB_REPOSITORY\" --workflow sibling-run.yml --branch \"$SYNC_BRANCH\" --limit 1 --json databaseId --jq '.[0].databaseId')\"\n";
    let answered = "          run=\"$(gh api --method POST";
    let plants: Vec<(&str, String, &str)> = vec![
        (
            "the run found as the latest on the branch",
            text.replacen(answered, &format!("{latest}          ignored=\"$(gh api --method POST"), 1),
            "`gh run list`",
        ),
        (
            "the run id not asked of the dispatch",
            text.replace(" -F return_run_details=true", ""),
            "the dispatch answered",
        ),
        (
            "the judge not dispatched",
            text.replace(
                "          gh workflow run sibling-judge.yml --repo \"$GITHUB_REPOSITORY\" --ref main -f run_id=\"$run\"\n",
                "",
            ),
            "the judge is dispatched",
        ),
        (
            "the judge dispatched on beta",
            text.replace("--ref main -f run_id=\"$run\"", "--ref beta -f run_id=\"$run\""),
            "the judge is dispatched",
        ),
        (
            "the wait's failure absorbed",
            text.replace("sleep 15\n          done\n", "sleep 15\n          done || true\n"),
            "`|| true`",
        ),
        (
            "the bound dropped",
            text.replace("        timeout-minutes: 45\n", ""),
            "bounded",
        ),
        (
            "the key named",
            text.replace(
                "          GH_TOKEN: ${{ github.token }}\n        run: |\n          set -euo pipefail\n          run=",
                &format!("          GH_TOKEN: ${{{{ secrets.{} }}}}\n        run: |\n          set -euo pipefail\n          run=", concat!("SIBLING_JUDGE", "_KEY")),
            ),
            "the judge's key",
        ),
    ];
    for (what, planted, needle) in plants {
        assert_ne!(planted, text, "{what}: the plant changed nothing");
        let errors = sync_stage_r_judge(&planted);
        assert!(
            errors.iter().any(|e| e.contains(needle)),
            "{what}: {errors:?}"
        );
        assert!(
            sync_stage_r(&planted)
                .iter()
                .any(|e| e.contains("not `SYNC_STAGE_R` byte for byte")),
            "{what}: the pin did not see it"
        );
    }
}

/// The re-read of PR #931's fold: a variable the pinned dispatch reads, redefined where the bytes
/// do not reach, is refused by its name in the spellings the scan reads; every other spelling is
/// held by `SYNC_FILE_DIGEST` (`the_sync_workflow_is_pinned_whole_by_its_digest_97`).
#[test]
fn every_variable_the_stage_r_dispatch_reads_has_its_one_definition_97() {
    let mut reads = variables_read(SYNC_STAGE_R);
    reads.sort();
    let mut listed: Vec<String> = SYNC_STAGE_R_READS
        .iter()
        .map(|(n, _)| (*n).to_owned())
        .collect();
    listed.sort();
    assert_eq!(
        reads, listed,
        "SYNC_STAGE_R_READS is not what SYNC_STAGE_R's run: lines read"
    );
    let text = read(SYNC_FILE);
    assert!(
        sync_stage_r_reads(&text).is_empty(),
        "{:?}",
        sync_stage_r_reads(&text)
    );
    assert!(sync(&text).is_empty(), "{:?}", sync(&text));
    let job = "    runs-on: ubuntu-latest\n";
    let pick = "      - name: Cherry-pick main's commits onto beta\n        id: pick\n        run: |\n          set -euo pipefail\n";
    assert_eq!(text.matches(job).count(), 1);
    assert_eq!(text.matches(pick).count(), 1);
    let plants: Vec<(&str, String, &str)> = vec![
        (
            "a job-level SYNC_BRANCH (the re-read's plant)",
            text.replace(job, &format!("{job}    env:\n      SYNC_BRANCH: beta\n")),
            "`SYNC_BRANCH`",
        ),
        (
            "a job-level flow mapping",
            text.replace(job, &format!("{job}    env: {{ SYNC_BRANCH: beta }}\n")),
            "`SYNC_BRANCH`",
        ),
        (
            "a quoted job-level key",
            text.replace(
                job,
                &format!("{job}    env:\n      \"SYNC_BRANCH\": beta\n"),
            ),
            "`SYNC_BRANCH`",
        ),
        (
            "the workflow's value changed",
            text.replace(
                "  SYNC_BRANCH: sync/main-into-beta\n",
                "  SYNC_BRANCH: beta\n",
            ),
            "`SYNC_BRANCH`",
        ),
        (
            "the workflow's definition moved to the job",
            text.replace("env:\n  SYNC_BRANCH: sync/main-into-beta\n", "")
                .replace(
                    job,
                    &format!("{job}    env:\n      SYNC_BRANCH: sync/main-into-beta\n"),
                ),
            "`SYNC_BRANCH`",
        ),
        (
            "a $GITHUB_ENV write",
            text.replace(
                pick,
                &format!("{pick}          echo \"SYNC_BRANCH=beta\" >> \"$GITHUB_ENV\"\n"),
            ),
            "`SYNC_BRANCH`",
        ),
        (
            "an export",
            text.replace(pick, &format!("{pick}          export SYNC_BRANCH=beta\n")),
            "`SYNC_BRANCH`",
        ),
        (
            "a job-level GH_TOKEN",
            text.replace(
                job,
                &format!("{job}    env:\n      GH_TOKEN: ${{{{ secrets.OTHER }}}}\n"),
            ),
            "`GH_TOKEN`",
        ),
        (
            "a step's GH_TOKEN of another value",
            text.replacen(
                "          GH_TOKEN: ${{ github.token }}\n",
                "          GH_TOKEN: ${{ secrets.OTHER }}\n",
                1,
            ),
            "`GH_TOKEN`",
        ),
        (
            "a job-level GH_HOST",
            text.replace(
                job,
                &format!("{job}    env:\n      GH_HOST: example.invalid\n"),
            ),
            "`GH_HOST`",
        ),
        (
            "a GH_REPO written to $GITHUB_ENV",
            text.replace(
                pick,
                &format!("{pick}          echo \"GH_REPO=someone/else\" >> \"$GITHUB_ENV\"\n"),
            ),
            "`GH_REPO`",
        ),
        (
            "GITHUB_REPOSITORY defined",
            text.replace(
                "env:\n  SYNC_BRANCH: sync/main-into-beta\n",
                "env:\n  SYNC_BRANCH: sync/main-into-beta\n  GITHUB_REPOSITORY: someone/else\n",
            ),
            "`GITHUB_REPOSITORY`",
        ),
    ];
    for (what, planted, named) in plants {
        assert_ne!(planted, text, "{what}: the plant changed nothing");
        let errors = sync(&planted);
        assert!(
            errors
                .iter()
                .any(|e| e.contains(named) && e.contains("stage R dispatch (#97)")),
            "{what}: {errors:?}"
        );
    }
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
            // the node oracle's judge and harness tests (#97): sibling_judge.py and
            // sibling_harness.py on hermetic fixtures, on every pull request
            ("judge-tests", "judge-tests"),
            ("vectors", "vectors"),
            ("fixtures", "fixtures"),
            ("front-page", "front page"),
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

/// The version job's test of a tag's form: `vX.Y.Z` or `vX.Y.Z-beta.N`, no other.
const TAG_FORMS: &str = r#"if [[ "$GITHUB_REF_NAME" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-beta\.(0|[1-9][0-9]*))?$ ]]; then"#;

/// The page job's two lines that make the page, whole: each carries the notes file and the
/// flags (the strength re-read's F-3: a prefix pin let either be dropped).
const PAGE_EDIT: &str = r#"gh release edit "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" --title "$title" --notes-file "$RUNNER_TEMP/notes.md" "${flags[@]}""#;
const PAGE_CREATE: &str = r#"gh release create "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" --verify-tag --title "$title" --notes-file "$RUNNER_TEMP/notes.md" "${flags[@]}""#;

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
    if !version.contains("section is empty; the Release page is made from that section") {
        errors.push("release.yml: the version job does not refuse an empty changelog section before the publish".to_owned());
    }
    // Two forms of tag and no other (RELEASING.md step 14; the captain's ruling T7): a tag the
    // regex refuses (`-rc.1`, `-alpha`, `+1`) stops the version job before anything is published
    if !version.contains(TAG_FORMS)
        || !version.contains(
            "is neither vX.Y.Z (cut from main) nor vX.Y.Z-beta.N (cut from beta); no other form is released",
        )
    {
        errors.push(
            "release.yml: the version job does not refuse a tag of another form than vX.Y.Z and vX.Y.Z-beta.N".to_owned(),
        );
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
            r#"gh release create "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" --verify-tag"#,
            "the page of the pushed tag alone",
        ),
        // The flags read into a variable on a line of their own, so that `set -e` stops the
        // step when `flags` fails: read inside `read <<< "$(...)"` the failure is lost, the
        // page goes out with no mark and GitHub's default makes a back-patch Latest (the
        // strength read of 2026-11-11, run under bash -e; the captain's ruling R1)
        (
            "\n          marks=\"$(python3 -B .github/scripts/front_pages.py flags \"$GITHUB_REF_NAME\")\"\n          read -r -a flags <<< \"$marks\"\n",
            "the flags on a line of their own, a failure stopping the step",
        ),
        ("set -euo pipefail", "a failing command stops the step"),
        // a page that exists (thirteen made by hand on 2026-11-11, or an earlier attempt) is
        // edited, never created twice, so re-running the failed job heals it
        (
            r#"if gh release view "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" > /dev/null 2>&1; then"#,
            "a page that exists is found",
        ),
        (
            r#"gh release edit "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY""#,
            "a page that exists is edited",
        ),
        ("persist-credentials: false", "the write token is not left in the checkout"),
        (
            "sed 's/^/::warning::/'",
            "every not recorded line of the notes a warning of the run",
        ),
    ] {
        if !page.contains(needle) {
            errors.push(format!("release.yml page: no `{needle}` ({why})"));
        }
    }
    for (line, what) in [(PAGE_CREATE, "create"), (PAGE_EDIT, "edit")] {
        if !page.lines().any(|l| l.trim() == line) {
            errors.push(format!(
                "release.yml page: the {what} line is not `{line}` whole (the notes file and the flags on it)"
            ));
        }
    }
    // a page for a version crates.io lacks, after a failed publish, or a reconciler run past a
    // failed page: neither job runs on any outcome but its `needs:` succeeding (F-3)
    for (name, body) in [("page", &page), ("front-pages", &job("front-pages"))] {
        for absorb in ["always()", "cancelled()", "continue-on-error", "failure()"] {
            if body.contains(absorb) {
                errors.push(format!(
                    "release.yml {name}: carries `{absorb}`; it runs only after its `needs:` succeeded"
                ));
            }
        }
    }
    if page.contains("<<< \"$(") {
        errors.push(
            "release.yml page: a command read inside `<<< \"$(...)\"`, its failure lost".to_owned(),
        );
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
        (
            "front_pages.py check --wait 3600",
            "the reconciler waits for what time heals",
        ),
        ("timeout-minutes: 75", "the wait is bounded past its hour"),
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
            r#"release.yml page: no `front_pages.py flags "$GITHUB_REF_NAME"` (prerelease and Latest from the version)"#,
            "release.yml page: no `\n          marks=\"$(python3 -B .github/scripts/front_pages.py flags \"$GITHUB_REF_NAME\")\"\n          read -r -a flags <<< \"$marks\"\n` (the flags on a line of their own, a failure stopping the step)",
        ]
    );
    let swallowed = release.replacen(
        "          marks=\"$(python3 -B .github/scripts/front_pages.py flags \"$GITHUB_REF_NAME\")\"\n          read -r -a flags <<< \"$marks\"\n",
        "          read -r -a flags <<< \"$(python3 -B .github/scripts/front_pages.py flags \"$GITHUB_REF_NAME\")\"\n",
        1,
    );
    assert_eq!(
        release_pages(&swallowed, &dispatch),
        [
            "release.yml page: no `\n          marks=\"$(python3 -B .github/scripts/front_pages.py flags \"$GITHUB_REF_NAME\")\"\n          read -r -a flags <<< \"$marks\"\n` (the flags on a line of their own, a failure stopping the step)",
            "release.yml page: a command read inside `<<< \"$(...)\"`, its failure lost",
        ]
    );
    let create_only = release.replacen(
        r#"          if gh release view "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" > /dev/null 2>&1; then"#,
        "          if false; then",
        1,
    );
    assert_eq!(
        release_pages(&create_only, &dispatch),
        [
            r#"release.yml page: no `if gh release view "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" > /dev/null 2>&1; then` (a page that exists is found)"#
        ]
    );
    let empty_section = release.replacen(
        "section is empty; the Release page",
        "section is empty; the page",
        1,
    );
    assert_eq!(
        release_pages(&empty_section, &dispatch),
        ["release.yml: the version job does not refuse an empty changelog section before the publish"]
    );
    let no_wait = release.replacen(
        "front_pages.py check --wait 3600",
        "front_pages.py check",
        1,
    );
    assert_eq!(
        release_pages(&no_wait, &dispatch),
        ["release.yml front-pages: no `front_pages.py check --wait 3600` (the reconciler waits for what time heals)"]
    );
    // T7: a third form of tag admitted
    let any_tag = release.replacen(
        TAG_FORMS,
        r#"if [[ "$GITHUB_REF_NAME" =~ ^v.+$ ]]; then"#,
        1,
    );
    assert_eq!(
        release_pages(&any_tag, &dispatch),
        ["release.yml: the version job does not refuse a tag of another form than vX.Y.Z and vX.Y.Z-beta.N"]
    );
    // T8: the flags dropped from the create line, the notes file from the edit line, and a
    // page made whatever the publish did
    let unmarked = release.replacen(
        &format!("{PAGE_CREATE}\n"),
        &format!("{}\n", PAGE_CREATE.replace(r#" "${flags[@]}""#, "")),
        1,
    );
    assert_eq!(
        release_pages(&unmarked, &dispatch),
        [format!("release.yml page: the create line is not `{PAGE_CREATE}` whole (the notes file and the flags on it)")]
    );
    let blank = release.replacen(
        &format!("{PAGE_EDIT}\n"),
        &format!(
            "{}\n",
            PAGE_EDIT.replace(r#" --notes-file "$RUNNER_TEMP/notes.md""#, "")
        ),
        1,
    );
    assert_eq!(
        release_pages(&blank, &dispatch),
        [format!("release.yml page: the edit line is not `{PAGE_EDIT}` whole (the notes file and the flags on it)")]
    );
    let always = release.replacen(
        "    name: Release page\n    needs: publish\n",
        "    name: Release page\n    needs: publish\n    if: always()\n",
        1,
    );
    assert_eq!(
        release_pages(&always, &dispatch),
        ["release.yml page: carries `always()`; it runs only after its `needs:` succeeded"]
    );
    let absorbed = release.replacen(
        "    name: Front pages agree\n    needs: page\n",
        "    name: Front pages agree\n    needs: page\n    continue-on-error: true\n",
        1,
    );
    assert_eq!(
        release_pages(&absorbed, &dispatch),
        ["release.yml front-pages: carries `continue-on-error`; it runs only after its `needs:` succeeded"]
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
