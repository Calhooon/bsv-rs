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
//! A version published once (#867; RELEASING.md step 8): the `version` job's last step is
//! `PUBLISHED_ONCE` byte for byte (a version crates.io lists, a tag with a Release page and a tag
//! that ran at another commit refused, an unreadable answer refused too), the job holds
//! `contents: read` and `actions: read`, absorbs no failure, and every other job of
//! `release.yml` waits for it.
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
            (
                "  group: sync-main-into-beta\n  cancel-in-progress: false\n",
                "one sync at a time, and one in progress is never cancelled (#958)",
            ),
            (
                SYNC_GROUP_STATED,
                "the header says what the group does to a run queued behind the stage R wait (#958)",
            ),
        ],
        &mut errors,
    );
    errors.extend(sync_stage_r(text));
    errors.extend(sync_stage_r_reads(text));
    errors.extend(sync_stage_r_judge(text));
    errors.extend(sync_stage_r_wait(text));
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
      # not completed in 40 minutes, fails the job where a person sees it. The wait is bounded by
      # the clock (budget, each poll's own timeout and one interval end inside the step's 45
      # minutes) and a poll that fails or hangs is read as not completed yet, so every way out of
      # the wait that is not `completed` prints the hand command with the run's id.
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
          budget=2400
          while [ "$SECONDS" -lt "$budget" ]; do
            if ! status="$(timeout 60 gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${run}" --jq '.status')"; then
              status="unread (its last poll failed)"
            fi
            if [ "$status" = completed ]; then break; fi
            sleep 15
          done
          if [ "$status" != completed ]; then
            echo "::error::stage R run ${run} is ${status:-unread} after $((SECONDS / 60)) minutes; once it completes: gh workflow run sibling-judge.yml --repo ${GITHUB_REPOSITORY} --ref main -f run_id=${run}"
            exit 1
          fi
          echo "stage R run ${run} completed; its judge, by hand if the next line fails: gh workflow run sibling-judge.yml --repo ${GITHUB_REPOSITORY} --ref main -f run_id=${run}"
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
    /// Never defined in the file: bash's own (`SECONDS`, the seconds since the step's shell
    /// started, which the wait's budget reads; an assignment anywhere would restart the clock).
    Shell,
}

/// Every variable the pinned dispatch steps read, with where it is defined; the test
/// `every_variable_the_stage_r_dispatch_reads_has_its_one_definition_97` holds this list equal
/// to what `SYNC_STAGE_R`'s `run:` lines read, so a variable added to the pin needs its row.
const SYNC_STAGE_R_READS: &[(&str, Definition)] = &[
    ("GH_TOKEN", Definition::Steps("${{ github.token }}")),
    ("GITHUB_REPOSITORY", Definition::Runner),
    ("SECONDS", Definition::Shell),
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
            Definition::Runner | Definition::Shell => {
                if !found.is_empty() {
                    errors.push(format!(
                        "sync: `{name}`, which the stage R dispatch (#97) reads, is defined ({}); it is the {}'s own, defined nowhere in the file",
                        lines(),
                        if matches!(defined, Definition::Shell) {
                            "shell"
                        } else {
                            "runner"
                        }
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
const SYNC_FILE_DIGEST: u64 = 0xc63a_c1d6_ac8b_0910;

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

/// The header's sentence on the sync's concurrency group (#958): since fix-97c the one job ends
/// with the stage R wait, so a run that pushed picks holds the group for up to the step's 45
/// minutes; GitHub keeps one pending run per group, so a third push to main in that window
/// replaces the queued second run, which then reads `cancelled` in Actions. Nothing is lost (the
/// newest run finds every commit beta lacks); the sentence is where a reader of that run looks.
const SYNC_GROUP_STATED: &str = "# only the newest waits and each one it replaced shows as cancelled. A cancelled sync run under\n# a newer one is the group's, not a failure: the newest run finds every commit beta lacks.\n";

/// The integer after `key` on a line of `step` (`budget=2400`, `sleep 15`, `timeout 60 gh`,
/// `timeout-minutes: 45`), each occurrence; a figure that is no plain integer (`sleep 2m`,
/// `budget="$B"`) is `None`: unreadable, so refused.
fn figures(step: &str, key: &str) -> Vec<Option<u64>> {
    step.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .flat_map(|line| {
            line.match_indices(key)
                .filter(|(at, _)| {
                    !line[..*at]
                        .chars()
                        .next_back()
                        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                })
                .map(|(at, _)| {
                    let rest = &line[at + key.len()..];
                    let word: String = rest
                        .chars()
                        .take_while(|c| !c.is_whitespace() && *c != ';' && *c != ')')
                        .collect();
                    word.parse::<u64>().ok()
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The stage R wait ends with its re-judge line (#958). Until then one failed status poll ended
/// the step under `set -e` (160 calls, each able to answer a 5xx) and 160 polls of 15 s plus the
/// API's time could pass the step's 45 minutes, either way with no line naming the hand command;
/// and no guard read the loop's figures (the cap guard's give-up rule reads `gh run watch` waits
/// alone). The rules, each refused by name: the loop is bounded by the clock, not by a count; the
/// poll is the condition of an `if !`, so its failure is read as not completed yet, and runs
/// under its own `timeout`, so a call that hangs is one failed poll; the budget, one poll's
/// timeout and one interval end at or under the step's `timeout-minutes` less two minutes; and
/// every `::error::` after the run's id is known carries the judge's hand command with that id.
fn sync_stage_r_wait(text: &str) -> Vec<String> {
    const MARGIN: u64 = 120;
    let mut errors = Vec::new();
    let Some(at) = text.find("      - name: Start the PR's stage R and its judge\n") else {
        return vec!["sync: no step `Start the PR's stage R and its judge` (#958)".to_owned()];
    };
    let step = &text[at..];
    let mut refuse = |what: &str| errors.push(format!("sync: the stage R wait {what} (#958)"));
    if !step.contains("          while [ \"$SECONDS\" -lt \"$budget\" ]; do\n") {
        refuse("is not `while [ \"$SECONDS\" -lt \"$budget\" ]; do`: the wait is bounded by the clock, whatever a poll costs");
    }
    if step.contains("seq ") {
        refuse("counts its polls (`seq `): a count bounds no time, each poll taking what the API takes");
    }
    let polls: Vec<&str> = step
        .lines()
        .filter(|line| line.contains("/actions/runs/${run}\""))
        .collect();
    if polls.is_empty() {
        refuse("polls no run by the id the dispatch answered");
    }
    for poll in &polls {
        if !poll.trim_start().starts_with("if ! status=\"$(timeout ") {
            refuse(&format!(
                "polls outside `if ! status=\"$(timeout N gh api ...)\"; then` (`{}`): a poll that fails ends the step under `set -e`, and one that hangs spends its timeout, with no re-judge line",
                poll.trim()
            ));
        }
    }
    if !step.contains("              status=\"unread (its last poll failed)\"\n") {
        refuse("gives a failed poll no status: it is read as not completed yet, by name");
    }
    let one = |key: &str, what: &str, errors: &mut Vec<String>| -> Option<u64> {
        match figures(step, key).as_slice() {
            [Some(n)] => Some(*n),
            found => {
                errors.push(format!(
                    "sync: the stage R wait has {} `{key}` ({what}), {found:?}; it has one, a plain integer (#958)",
                    found.len()
                ));
                None
            }
        }
    };
    let minutes = one("timeout-minutes: ", "the step's bound", &mut errors);
    let budget = one("budget=", "the wait's seconds", &mut errors);
    let poll = one("timeout ", "one poll's seconds", &mut errors);
    let interval = one("sleep ", "the interval's seconds", &mut errors);
    if let (Some(minutes), Some(budget), Some(poll), Some(interval)) =
        (minutes, budget, poll, interval)
    {
        let worst = budget + poll + interval;
        if worst + MARGIN > minutes * 60 {
            errors.push(format!(
                "sync: the stage R wait can run {worst} s (budget {budget} + one poll {poll} + one interval {interval}), past the step's {minutes} minutes less {MARGIN} s: the step would be killed before its re-judge line (#958)"
            ));
        }
    }
    let known = step.find("echo \"stage R run ${run} on ").unwrap_or(0);
    for line in step[known..].lines().filter(|l| l.contains("::error::")) {
        if !line.contains("gh workflow run sibling-judge.yml --repo ${GITHUB_REPOSITORY} --ref main -f run_id=${run}") {
            errors.push(format!(
                "sync: the stage R wait fails without its re-judge line (`{}`): every failure after the run's id is known names the hand command with the id (#958)",
                line.trim()
            ));
        }
    }
    errors
}

/// #958's plants on the wait, each refused by its rule's name and seen by the pin: the count
/// back (`seq 1 200`), the poll back under bare `set -e`, the poll's own timeout dropped, each
/// figure moved past the step's bound or made unreadable, the failure's line without its hand
/// command; and the header's sentence on the group removed, or a run in progress cancelled.
#[test]
fn the_sync_stage_r_wait_is_bounded_by_the_clock_and_ends_with_its_rejudge_line_958() {
    let text = read(SYNC_FILE);
    assert!(
        sync_stage_r_wait(&text).is_empty(),
        "{:?}",
        sync_stage_r_wait(&text)
    );
    let poll = "            if ! status=\"$(timeout 60 gh api \"repos/${GITHUB_REPOSITORY}/actions/runs/${run}\" --jq '.status')\"; then\n              status=\"unread (its last poll failed)\"\n            fi\n";
    let bare = "            status=\"$(gh api \"repos/${GITHUB_REPOSITORY}/actions/runs/${run}\" --jq '.status')\"\n";
    let clock = "          while [ \"$SECONDS\" -lt \"$budget\" ]; do\n";
    let hand = "; once it completes: gh workflow run sibling-judge.yml --repo ${GITHUB_REPOSITORY} --ref main -f run_id=${run}\"\n";
    for needle in [
        poll,
        clock,
        hand,
        "          budget=2400\n",
        "            sleep 15\n",
    ] {
        assert_eq!(text.matches(needle).count(), 1, "{needle}");
    }
    let plants: Vec<(&str, String, &str)> = vec![
        (
            "the count back, at 200 polls",
            text.replace(clock, "          for _ in $(seq 1 200); do\n"),
            "counts its polls",
        ),
        (
            "the poll back under bare set -e",
            text.replace(poll, bare),
            "polls outside `if ! status=",
        ),
        (
            "the poll's own timeout dropped",
            text.replace(
                "$(timeout 60 gh api \"repos/${GITHUB_REPOSITORY}/actions/runs/",
                "$(gh api \"repos/${GITHUB_REPOSITORY}/actions/runs/",
            ),
            "polls outside `if ! status=",
        ),
        (
            "a failed poll's status dropped",
            text.replace(
                "              status=\"unread (its last poll failed)\"\n",
                "              true\n",
            ),
            "gives a failed poll no status",
        ),
        (
            "the budget at the step's 45 minutes",
            text.replace("          budget=2400\n", "          budget=2700\n"),
            "can run 2775 s",
        ),
        (
            "the budget inside the margin",
            text.replace("          budget=2400\n", "          budget=2520\n"),
            "can run 2595 s",
        ),
        (
            "the interval at ten minutes",
            text.replace("            sleep 15\n", "            sleep 600\n"),
            "can run 3060 s",
        ),
        (
            "a poll allowed five minutes",
            text.replace("$(timeout 60 gh api", "$(timeout 300 gh api"),
            "can run 2715 s",
        ),
        (
            "the step's bound lowered to the budget",
            text.replace(
                "        timeout-minutes: 45\n",
                "        timeout-minutes: 40\n",
            ),
            "past the step's 40 minutes",
        ),
        (
            "an interval that is no plain integer",
            text.replace("            sleep 15\n", "            sleep 2m\n"),
            "has 1 `sleep ` (the interval's seconds), [None]",
        ),
        (
            "a second budget",
            text.replace(
                "          budget=2400\n",
                "          budget=2400\n          budget=9000\n",
            ),
            "has 2 `budget=`",
        ),
        (
            "the failure's line without its hand command",
            text.replace(hand, "\"\n"),
            "fails without its re-judge line",
        ),
    ];
    for (what, planted, needle) in plants {
        assert_ne!(planted, text, "{what}: the plant changed nothing");
        let errors = sync_stage_r_wait(&planted);
        assert!(
            errors
                .iter()
                .any(|e| e.contains(needle) && e.contains("(#958)")),
            "{what}: {errors:?}"
        );
        assert!(
            sync(&planted).iter().any(|e| e.contains(needle)),
            "{what}: sync() did not carry it"
        );
        assert!(
            sync_stage_r(&planted)
                .iter()
                .any(|e| e.contains("not `SYNC_STAGE_R` byte for byte")),
            "{what}: the pin did not see it"
        );
    }
    let group: Vec<(&str, String, &str)> = vec![
        (
            "the header's sentence removed",
            text.replace(SYNC_GROUP_STATED, ""),
            "the header says what the group does",
        ),
        (
            "a sync in progress cancelled by the next",
            text.replace(
                "  cancel-in-progress: false\n",
                "  cancel-in-progress: true\n",
            ),
            "one in progress is never cancelled",
        ),
    ];
    for (what, planted, needle) in group {
        assert_ne!(planted, text, "{what}: the plant changed nothing");
        let errors = sync(&planted);
        assert!(
            errors
                .iter()
                .any(|e| e.contains(needle) && e.contains("(#958)")),
            "{what}: {errors:?}"
        );
        assert!(
            !sync_digest_refusals(&planted).is_empty(),
            "{what}: the digest did not see it"
        );
    }
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

/// `run_lines` on sample texts (#958): the reader behind the stage R step's variable rule had no
/// test of its own, and with its block arm gone every test stayed green, the one-line `run:` of
/// ci.yml's dispatch reading the same names as the block. Each sample names what a block is: the
/// lines below a `run: |` indented deeper than the key, a blank line among them, up to the next
/// line at the key's indent or shallower.
#[test]
fn run_lines_reads_a_one_line_run_and_every_line_of_a_block_958() {
    let one = "      - name: a\n        env:\n          A: b\n        run: echo \"$ONE\"\n";
    assert_eq!(run_lines(one), ["        run: echo \"$ONE\""]);
    let blank = "        run: |\n          echo \"$TWO\"\n\n          echo \"$THREE\"\n";
    assert_eq!(
        run_lines(blank),
        [
            "        run: |",
            "          echo \"$TWO\"",
            "",
            "          echo \"$THREE\""
        ]
    );
    let closed = "        run: |\n          echo \"$FOUR\"\n        env:\n          B: \"$NOT_A_RUN_LINE\"\n      - name: next\n";
    assert_eq!(
        run_lines(closed),
        ["        run: |", "          echo \"$FOUR\""]
    );
    let two = "        run: |\n          one\n      - name: b\n        run: |\n          two\n          three\n      - name: c\n        run: four\n";
    assert_eq!(
        run_lines(two),
        [
            "        run: |",
            "          one",
            "        run: |",
            "          two",
            "          three",
            "        run: four"
        ]
    );
    assert!(run_lines("      - name: a\n        with:\n          x: y\n").is_empty());
    assert_eq!(
        variables_read(closed),
        ["B", "FOUR"],
        "a block's lines are read for `$NAME`, an `env:` value is not"
    );
}

/// A variable the stage R step reads inside its `run: |` block alone is seen by the variable rule
/// (#958): planted on the block's own echo line of `SYNC_STAGE_R`, it is a name the list lacks, so
/// `every_variable_the_stage_r_dispatch_reads_has_its_one_definition_97` would refuse the pin until
/// the name has its row.
#[test]
fn a_variable_read_only_inside_the_stage_r_block_is_read_958() {
    let line = "          echo \"stage R run ${run} on ${SYNC_BRANCH}\"\n";
    assert_eq!(SYNC_STAGE_R.matches(line).count(), 1);
    for spelled in ["$NEW_NAME", "${NEW_NAME}"] {
        let planted = SYNC_STAGE_R.replace(
            line,
            &format!("          echo \"stage R run ${{run}} on ${{SYNC_BRANCH}} {spelled}\"\n"),
        );
        assert_ne!(planted, SYNC_STAGE_R);
        let reads = variables_read(&planted);
        assert!(
            reads.iter().any(|name| name == "NEW_NAME"),
            "{spelled}: {reads:?}"
        );
        assert!(
            !SYNC_STAGE_R_READS
                .iter()
                .any(|(name, _)| *name == "NEW_NAME"),
            "the list names the plant"
        );
    }
}

/// What the ritual says of the judge's silences and of a cancelled sync (#958), read from
/// `RELEASING.md` beside the lines of the two workflows that make each sentence true: while the
/// trampoline's jobs test the ref `main` the ritual names the default branch among the silences,
/// with the read-back that prints it and the repository's visibility; while the sync runs in a
/// group that is never cancelled in progress and waits for stage R, the direction rule says a
/// cancelled sync run under a newer one is the group's; and the sentence on what `main` takes of
/// the sync names the whole step.
fn releasing_refusals(releasing: &str, judge: &str, sync: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let mut need = |holds: bool, needle: &str, why: &str| {
        if holds && !releasing.contains(needle) {
            errors.push(format!("RELEASING.md: {why}; it lacks `{needle}` (#958)"));
        }
    };
    let on_main = judge.contains("if: github.ref == 'refs/heads/main'");
    need(
        on_main,
        "a default branch that is no longer `main`",
        "the trampoline's jobs run on the ref `main` alone, so a changed default branch silences the judge",
    );
    need(
        on_main,
        "a repository that is no longer public",
        "`report` reads through a token of `checks: write` alone, so a private repository silences the judge",
    );
    need(
        on_main,
        "gh api repos/Calhooon/bsv-rs --jq '{default_branch, visibility}'",
        "the two settings have their read-back",
    );
    let grouped = sync.contains("  group: sync-main-into-beta\n  cancel-in-progress: false\n")
        && sync.contains("      - name: Start the PR's stage R and its judge\n");
    need(
        grouped,
        "A cancelled sync run under a newer one is the group's, not a failure",
        "the sync holds its group through the stage R wait, so a replaced pending run reads cancelled",
    );
    need(
        grouped,
        "the sync workflow's step that starts stage R, waits for it and dispatches its judge",
        "`main` carries the whole step, its wait and its dispatch of the judge included",
    );
    errors
}

#[test]
fn releasing_names_the_settings_that_silence_the_judge_and_the_syncs_cancelled_run_958() {
    let releasing = read("RELEASING.md");
    let judge = read(".github/workflows/sibling-judge.yml");
    let sync = read(SYNC_FILE);
    let errors = releasing_refusals(&releasing, &judge, &sync);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    assert_eq!(
        judge.matches("github.ref == 'refs/heads/main'").count(),
        2,
        "both jobs of the trampoline test the ref"
    );
    for needle in [
        "a default branch that is no longer `main`",
        "a repository that is no longer public",
        "{default_branch, visibility}",
        "A cancelled sync run under a newer one is the group's, not a failure",
        "starts stage R, waits for it and dispatches its judge",
    ] {
        let planted = releasing.replace(needle, "");
        assert_ne!(planted, releasing, "{needle}");
        let errors = releasing_refusals(&planted, &judge, &sync);
        assert!(
            errors.iter().any(|e| e.contains("(#958)")),
            "{needle}: {errors:?}"
        );
    }
    assert!(releasing_refusals("", "", "").is_empty());
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

/// The version job's last step (#867), byte for byte: the refusal of a version that is already
/// published and of a tag an earlier run ran at another commit.
const PUBLISHED_ONCE: &str = r##"      # A version is published once, from one commit (#867; RELEASING.md steps 8 and 9). The
      # repository's ruleset forbids moving or deleting a `v*` tag; this step is the workflow's
      # own refusal, should the ruleset ever change. It refuses, before any job that publishes
      # starts (every one of them needs this job), a tag whose version crates.io's index
      # lists (yanked included), a tag that has a Release page, and a tag an earlier run of
      # this workflow ran at another commit (v0.9.0-beta.4 ran at three on 2026-10-30). It
      # fails closed: an answer it cannot read (crates.io or GitHub unreachable, an index
      # without 0.8.9, a status other than 200 or 404, a run list without this run's own
      # commit) refuses too. Nothing here is consumed, so "Re-run failed jobs" tries again.
      - name: The version is not published and the tag ran at no other commit
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -euo pipefail
          version="${GITHUB_REF_NAME#v}"
          curl -fsS --retry 3 --max-time 60 -o "$RUNNER_TEMP/index.jsonl" https://index.crates.io/bs/v-/bsv-rs
          listed="$(jq -r 'select(.name == "bsv-rs") | .vers' "$RUNNER_TEMP/index.jsonl")"
          if ! grep -qxF '0.8.9' <<< "$listed"; then
            echo "::error::crates.io's index for bsv-rs could not be read (its answer does not list 0.8.9); nothing is published on an answer that cannot be read: re-run this job when https://index.crates.io/bs/v-/bsv-rs answers"
            exit 1
          fi
          if grep -qxF -- "$version" <<< "$listed"; then
            echo "::error::bsv-rs ${version} is already on crates.io; a version is published once (RELEASING.md step 9). Leave the tag where it is and ship the fix as the next version, by a release pull request and a new tag (step 8)"
            exit 1
          fi
          page="$(curl -sS --retry 3 --max-time 60 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${GH_TOKEN}" -H 'Accept: application/vnd.github+json' "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/releases/tags/${GITHUB_REF_NAME}")"
          case "$page" in
            404) ;;
            200)
              echo "::error::${GITHUB_REF_NAME} already has a Release page (gh release view ${GITHUB_REF_NAME}); a version is released once. If the page was made by mistake for a version crates.io does not list, delete the page and re-run this job; otherwise ship the next version (RELEASING.md step 8)"
              exit 1
              ;;
            *)
              echo "::error::GitHub answered ${page} for the Release page of ${GITHUB_REF_NAME}; nothing is published on an answer that cannot be read: re-run this job"
              exit 1
              ;;
          esac
          gh run list --repo "$GITHUB_REPOSITORY" --workflow release.yml --branch "$GITHUB_REF_NAME" --event push --limit 100 --json headSha,headBranch > "$RUNNER_TEMP/runs.json"
          count="$(jq -r 'if type == "array" then length else error("not a list") end' "$RUNNER_TEMP/runs.json")"
          if [ "$count" -ge 100 ]; then
            echo "::error::100 runs of release.yml or more name ${GITHUB_REF_NAME}; the list cannot be read whole, so the tag is refused: ship the next version (RELEASING.md step 8)"
            exit 1
          fi
          commits="$(jq -r --arg tag "$GITHUB_REF_NAME" '[.[] | select(.headBranch == $tag) | .headSha] | unique | .[]' "$RUNNER_TEMP/runs.json")"
          if ! grep -qxF -- "$GITHUB_SHA" <<< "$commits"; then
            echo "::error::the runs of release.yml for ${GITHUB_REF_NAME} do not list this run's own commit ${GITHUB_SHA}; nothing is published on an answer that cannot be read: re-run this job"
            exit 1
          fi
          others="$(grep -vxF -- "$GITHUB_SHA" <<< "$commits" || true)"
          if [ -n "$others" ]; then
            echo "::error::${GITHUB_REF_NAME} was moved: release.yml ran for it at $(tr '\n' ' ' <<< "$others")and now at ${GITHUB_SHA}. A v* tag is never moved (RELEASING.md step 8): leave it, say in its CHANGELOG.md section that it was tagged and never published, and ship the next version"
            exit 1
          fi
          echo "bsv-rs ${version}: not on crates.io, no Release page, release.yml ran for ${GITHUB_REF_NAME} at ${GITHUB_SHA} alone"
"##;

/// The ids of the jobs under `jobs:`, in order.
fn job_ids(text: &str) -> Vec<&str> {
    block(text, 0, "jobs:")
        .unwrap_or_default()
        .into_iter()
        .filter(|l| {
            l.starts_with("  ")
                && !l.starts_with("   ")
                && !l.trim_start().starts_with('#')
                && l.trim_end().ends_with(':')
        })
        .map(|l| l.trim().trim_end_matches(':'))
        .collect()
}

/// What release.yml must hold so that a version is published once, from one commit (#867):
/// `PUBLISHED_ONCE` the version job's last step, byte for byte; the job's permissions the two
/// its reads need; no failure of the job absorbed; and every other job behind it, directly or
/// through a job that is (so nothing is published, and no page made, before it has passed).
fn release_once(release: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let job = |name: &str| block(release, 2, &format!("{name}:")).unwrap_or_default();
    let version = job("version").join("\n");
    let head = "      # A version is published once, from one commit (#867;";
    match version.find(head) {
        None => errors.push(
            "release.yml: the version job does not refuse a version that is already published (#867): no `PUBLISHED_ONCE` step".to_owned(),
        ),
        Some(at) => {
            let tail = version[at..].trim_end();
            let pin = PUBLISHED_ONCE.trim_end();
            if tail != pin {
                let found = tail
                    .lines()
                    .zip(pin.lines())
                    .position(|(a, b)| a != b)
                    .unwrap_or_else(|| tail.lines().count().min(pin.lines().count()));
                errors.push(format!(
                    "release.yml: the version job's last step is not `PUBLISHED_ONCE` byte for byte to the job's end (#867); line {} of the pin is `{}`, found `{}`",
                    found + 1,
                    pin.lines().nth(found).unwrap_or("<end>"),
                    tail.lines().nth(found).unwrap_or("<end>"),
                ));
            }
        }
    }
    if !version
        .contains("\n    permissions:\n      contents: read\n      actions: read\n    steps:\n")
    {
        errors.push(
            "release.yml: the version job's permissions are not `contents: read` and `actions: read` alone (the run list needs the second, #867)".to_owned(),
        );
    }
    for line in version.lines() {
        let key = line.trim().trim_start_matches("- ");
        if key.starts_with("if:") || key.starts_with("continue-on-error") {
            errors.push(format!(
                "release.yml: the version job carries `{}`; every step of it runs and none of its failures is absorbed (#867)",
                line.trim()
            ));
        }
    }
    // every other job waits for the version job, itself or through a job that does
    let ids = job_ids(release);
    let needs = |name: &str| -> Vec<String> {
        job(name)
            .iter()
            .find_map(|l| l.strip_prefix("    needs:"))
            .map(|list| {
                list.trim()
                    .trim_matches(|c| c == '[' || c == ']')
                    .split(',')
                    .map(|n| n.trim().to_owned())
                    .filter(|n| !n.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut behind: Vec<String> = vec!["version".to_owned()];
    loop {
        let more: Vec<String> = ids
            .iter()
            .filter(|id| !behind.iter().any(|b| b == *id))
            .filter(|id| needs(id).iter().any(|n| behind.contains(n)))
            .map(|id| (*id).to_owned())
            .collect();
        if more.is_empty() {
            break;
        }
        behind.extend(more);
    }
    for id in &ids {
        if !behind.iter().any(|b| b == id) {
            errors.push(format!(
                "release.yml: job `{id}` does not wait for the version job (`needs:`), so it could run for a version the job refuses (#867)"
            ));
        }
        let body = job(id).join("\n");
        if *id != "version"
            && (body.contains("always()")
                || body.contains("failure()")
                || body.contains("cancelled()"))
        {
            errors.push(format!(
                "release.yml: job `{id}` runs on a failed or cancelled `needs:`; nothing runs past a refused version job (#867)"
            ));
        }
    }
    if !needs("publish").iter().any(|n| n == "version") {
        errors.push(
            "release.yml: `publish` does not name `version` in its `needs:` (#867)".to_owned(),
        );
    }
    errors
}

#[test]
fn a_tags_run_refuses_a_version_that_is_already_published_867() {
    let release = read(".github/workflows/release.yml");
    let errors = release_once(&release);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    assert_eq!(
        job_ids(&release),
        [
            "version",
            "ci",
            "docs",
            "msrv",
            "features",
            "machete",
            "bench",
            "publish",
            "page",
            "front-pages"
        ]
    );
}

#[test]
fn a_release_whose_refusal_is_weakened_absorbed_or_bypassed_is_refused_867() {
    let release = read(".github/workflows/release.yml");
    let pin_message = |line: usize, pinned: &str, found: &str| {
        format!(
            "release.yml: the version job's last step is not `PUBLISHED_ONCE` byte for byte to the job's end (#867); line {line} of the pin is `{pinned}`, found `{found}`"
        )
    };
    let plant = |from: &str, to: &str| {
        assert_eq!(
            release.matches(from).count(),
            1,
            "the plant's text `{from}` is in release.yml once"
        );
        release.replacen(from, to, 1)
    };
    // the step gone
    let gone = plant(PUBLISHED_ONCE, "");
    assert_eq!(
        release_once(&gone),
        ["release.yml: the version job does not refuse a version that is already published (#867): no `PUBLISHED_ONCE` step"]
    );
    // each of the three refusals, and each closed failure, turned into a pass
    for (from, to) in [
        // the index's read absorbed
        (
            "          curl -fsS --retry 3 --max-time 60 -o \"$RUNNER_TEMP/index.jsonl\" https://index.crates.io/bs/v-/bsv-rs\n",
            "          curl -fsS --retry 3 --max-time 60 -o \"$RUNNER_TEMP/index.jsonl\" https://index.crates.io/bs/v-/bsv-rs || true\n",
        ),
        // an index that does not list a known version read as an answer
        ("          if ! grep -qxF '0.8.9' <<< \"$listed\"; then\n", "          if false; then\n"),
        // a listed version published again
        ("          if grep -qxF -- \"$version\" <<< \"$listed\"; then\n", "          if false; then\n"),
        // a status that is neither 200 nor 404 read as no page
        ("            404) ;;\n", "            404|5*) ;;\n"),
        // an earlier run at another commit let through
        ("          if [ -n \"$others\" ]; then\n", "          if false; then\n"),
        // a run list without this run's own commit trusted
        ("          if ! grep -qxF -- \"$GITHUB_SHA\" <<< \"$commits\"; then\n", "          if false; then\n"),
        // a failing command no longer stopping the step
        ("          set -euo pipefail\n          version=\"${GITHUB_REF_NAME#v}\"\n          curl", "          version=\"${GITHUB_REF_NAME#v}\"\n          curl"),
    ] {
        let errors = release_once(&plant(from, to));
        assert_eq!(errors.len(), 1, "{from}: {errors:?}");
        assert!(
            errors[0].starts_with("release.yml: the version job's last step is not `PUBLISHED_ONCE` byte for byte"),
            "{from}: {errors:?}"
        );
    }
    // a step added after it, where it could publish or undo the refusal's exit
    let after = plant(
        "\n  ci:\n    name: CI\n",
        "      - name: late\n        run: echo late\n\n  ci:\n    name: CI\n",
    );
    assert_eq!(
        release_once(&after),
        [pin_message(
            PUBLISHED_ONCE.trim_end().lines().count() + 1,
            "<end>",
            "      - name: late"
        )]
    );
    // the failure absorbed
    let absorbed = plant(
        "      - name: The version is not published and the tag ran at no other commit\n",
        "      - name: The version is not published and the tag ran at no other commit\n        continue-on-error: true\n",
    );
    let errors = release_once(&absorbed);
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert_eq!(
        errors[1],
        "release.yml: the version job carries `continue-on-error: true`; every step of it runs and none of its failures is absorbed (#867)"
    );
    // the permission the run list needs dropped
    let unread = plant(
        "      contents: read\n      actions: read\n    steps:\n",
        "      contents: read\n    steps:\n",
    );
    assert_eq!(
        release_once(&unread),
        ["release.yml: the version job's permissions are not `contents: read` and `actions: read` alone (the run list needs the second, #867)"]
    );
    // the publish no longer behind the version job
    let loose = plant(
        "    needs: [version, ci, docs, msrv, features, machete]\n",
        "    needs: [ci, docs, msrv, features, machete]\n",
    );
    assert_eq!(
        release_once(&loose),
        ["release.yml: `publish` does not name `version` in its `needs:` (#867)"]
    );
    // a called workflow started beside the version job, and the publish behind it alone
    let beside = release
        .replacen("    name: CI\n    needs: version\n", "    name: CI\n", 1)
        .replacen(
            "    needs: [version, ci, docs, msrv, features, machete]\n",
            "    needs: [ci]\n",
            1,
        );
    assert_eq!(
        release_once(&beside),
        [
            "release.yml: job `ci` does not wait for the version job (`needs:`), so it could run for a version the job refuses (#867)",
            "release.yml: job `publish` does not wait for the version job (`needs:`), so it could run for a version the job refuses (#867)",
            "release.yml: job `page` does not wait for the version job (`needs:`), so it could run for a version the job refuses (#867)",
            "release.yml: job `front-pages` does not wait for the version job (`needs:`), so it could run for a version the job refuses (#867)",
            "release.yml: `publish` does not name `version` in its `needs:` (#867)",
        ]
    );
    // the publish run whatever the version job answered
    let always = plant(
        "    name: Publish to crates.io\n    needs: [version, ci, docs, msrv, features, machete]\n",
        "    name: Publish to crates.io\n    needs: [version, ci, docs, msrv, features, machete]\n    if: always()\n",
    );
    assert_eq!(
        release_once(&always),
        ["release.yml: job `publish` runs on a failed or cancelled `needs:`; nothing runs past a refused version job (#867)"]
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
