//! Advisories are read by the clock that moves them, never by a pull request (#1034).
//!
//! The RustSec database is an outside clock: a new entry against a transitive dependency
//! is no change of any pull request, and it turned a required check red on pull requests
//! that changed nothing related (the stack's ruling of 2026-11-17, `bsv-stack-lean`
//! `docs/DECISIONS-2026-10-19.md` 27.5, adopted here by #1034). So the four checks of
//! `cargo-deny` are read at three places, and this file pins each:
//!
//! - a pull request and a push: the `deny` step of `ci.yml`'s `lint` job reads `bans`,
//!   `licenses` and `sources`, functions of the tree, on the three graphs (all features, the
//!   Cloudflare wasm32 slice, default features) and never names `advisories`;
//! - once a day and on a dispatch: `advisories.yml` reads `advisories` for `main` and for
//!   `beta` on the same three graphs and keeps one issue a line (`advisories: <line>`), with
//!   `contents: read` and `issues: write` alone, no secret, every action pinned by its sha;
//! - a version tag: `release.yml`'s `advisories` job reads all four checks on the three
//!   graphs behind the version job, and `publish` waits for it, so nothing is released with
//!   an advisory nobody has looked at;
//! - `deny.toml` ignores no advisory: a finding is answered by a dependency change.
//!
//! Read at the string level, as `arch_duplicate_versions_104.rs` reads the same step; no
//! network, no environment. Each rule is shown to refuse the edit that would break it.
//!
//! The daily workflow raises the alarm and gates nothing, so a change that silences it (the
//! advisories step's `set +e` dropped, the unjudged run's `exit 1` made `exit 0`, the issue step
//! put behind a condition, a branch flipped) would leave every named rule green: the workflow
//! from its `on:` line to its end is pinned byte for byte as [`DAILY_PINNED`], as `SIBLING_JOB`
//! pins the `sibling` job in `arch_ci_pr_runs_the_required_set.rs`, a failure naming the line of
//! `advisories.yml`, the line pinned and the line found (#1034's fold). A pin is of the bytes: a
//! deliberate change of the workflow moves the pin in the same commit.
#![allow(clippy::expect_used, clippy::panic)]

const CI: &str = ".github/workflows/ci.yml";
const DAILY: &str = ".github/workflows/advisories.yml";
const RELEASE: &str = ".github/workflows/release.yml";
const DENY_TOML: &str = "deny.toml";

/// `advisories.yml` from its `on:` line to its end, byte for byte (the header's prose above it
/// is free). The named rules of [`daily_errors`] say why a line matters; this pin says that no
/// other line moved: the advisories step's `set +e` and its `exit 0`, the issue step's every
/// branch and exit, the issue's lookup, the job's keys and the lockfile step each change the
/// run's report without changing what cargo-deny checks, and none of them is caught by a named
/// rule (the strength read of #1035; 27 of 28 such plants passed the suite before this pin).
/// A deliberate change of the workflow moves this constant in the same commit.
const DAILY_PINNED: &str = r##"on:
  schedule:
    - cron: "23 6 * * *"
  workflow_dispatch:

permissions:
  contents: read
  issues: write

# one run at a time, never cancelled: two runs close together could each open the line's issue
concurrency:
  group: advisories
  cancel-in-progress: false

jobs:
  advisories:
    name: advisories (${{ matrix.line }})
    runs-on: ubuntu-latest
    timeout-minutes: 15
    strategy:
      fail-fast: false
      matrix:
        line: [main, beta]
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          ref: ${{ matrix.line }}
          persist-credentials: false

      - name: Install Rust
        uses: dtolnay/rust-toolchain@e2a55d2ffb04f378e9626c28d38b36d230d1e12f # v1
        with:
          toolchain: stable

      # the same pinned release binary as ci.yml's `deny` step and release.yml's job
      - name: Install cargo-deny 0.20.2
        uses: taiki-e/install-action@682ce6c3c696a4cd5168a05f98e51aa02b877941 # v2.89.1
        with:
          tool: cargo-deny@0.20.2

      - name: Resolve the lockfile
        run: cargo generate-lockfile

      # Each graph to a log and an exit code of its own; the step itself never fails on a
      # finding. No colour, so the next step reads `error[...]` at a line's start.
      - name: advisories
        run: |
          set +e
          cargo-deny --color never --locked --all-features check advisories > "$RUNNER_TEMP/advisories-all.log" 2>&1
          echo "$?" > "$RUNNER_TEMP/advisories-all.code"
          cargo-deny --color never --locked --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm" --target wasm32-unknown-unknown check advisories > "$RUNNER_TEMP/advisories-wasm32.log" 2>&1
          echo "$?" > "$RUNNER_TEMP/advisories-wasm32.code"
          cargo-deny --color never --locked check advisories > "$RUNNER_TEMP/advisories-default.log" 2>&1
          echo "$?" > "$RUNNER_TEMP/advisories-default.code"
          for graph in all wasm32 default; do
            echo "::group::$graph (exit $(cat "$RUNNER_TEMP/advisories-$graph.code"))"
            tail -n 200 "$RUNNER_TEMP/advisories-$graph.log"
            echo "::endgroup::"
          done
          exit 0

      - name: Open, rewrite or close the line's issue
        env:
          GH_TOKEN: ${{ github.token }}
          LINE: ${{ matrix.line }}
        run: |
          set -euo pipefail
          title="advisories: $LINE"
          sha=$(git rev-parse --short=8 HEAD)
          run_url="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"

          # A finding is an `error[...]` of an advisory's kind (a vulnerability, a notice, an
          # unmaintained or unsound crate, a yanked version). A graph that failed otherwise is
          # the run's own fault, never a finding: a log line of cargo-deny's `[ERROR]` (a config
          # it could not read, a database it could not fetch, a graph it could not resolve), a
          # diagnostic of another kind (a config's `unexpected-keys`, a registry's
          # `index-failure`), or none; a code that cannot be read is the same. Each answer was
          # shown by a run of cargo-deny 0.20.2 (tests/arch_advisories_answers_1034.rs).
          findings=""
          unjudged=""
          advisory='^error\[(vulnerability|notice|unmaintained|unsound|yanked)\]'
          for graph in all wasm32 default; do
            log="$RUNNER_TEMP/advisories-$graph.log"
            code=$(cat "$RUNNER_TEMP/advisories-$graph.code")
            if [[ "$code" == "0" ]]; then
              continue
            fi
            fault=$(grep -E '^error(\[[a-z-]+\])?: |^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8} \[ERROR\] ' "$log" | grep -v -E "$advisory" || true)
            kinds=$(grep -o -E "$advisory" "$log" | sort | uniq -c | sed -E 's/^ *([0-9]+) error\[([a-z-]+)\]/\2: \1/' | paste -sd ',' - | sed 's/,/, /g' || true)
            if [[ -n "$fault" || -z "$kinds" ]]; then
              unjudged="$unjudged $graph"
              continue
            fi
            ids=$(grep -o -E 'ID: RUSTSEC-[0-9]{4}-[0-9]{4}' "$log" | cut -d' ' -f2 | sort -u | paste -sd ' ' - || true)
            findings="${findings}- \`$graph\`: $kinds; advisory ids: ${ids:-none named (a yanked crate carries no id)}"$'\n'
          done
          if [[ -n "$unjudged" ]]; then
            echo "::error::cargo-deny could not judge:$unjudged (it failed with no advisory's finding, or with a fault of its own). This run could not judge \`$LINE\`; its issue is left as it stands"
            exit 1
          fi

          # Every page of the open issues, so an old issue is found again and never opened
          # twice; pull requests share the listing and are skipped.
          nums=$(gh api --paginate "repos/$GITHUB_REPOSITORY/issues?state=open&per_page=100" \
            --jq ".[] | select(.pull_request == null and .title == \"$title\") | .number")
          num=$(printf '%s\n' "$nums" | head -n 1)

          if [[ -z "$findings" ]]; then
            # every open issue of this title, should two ever have been opened
            for n in $nums; do
              gh api -X POST "repos/$GITHUB_REPOSITORY/issues/$n/comments" --silent \
                -f body="The advisories check is clean on \`$LINE\` at \`$sha\`, on the three graphs ($run_url). Closing."
              gh api -X PATCH "repos/$GITHUB_REPOSITORY/issues/$n" --silent -f state=closed
              echo "clean: closed issue $n"
            done
            [[ -n "$num" ]] || echo "clean: no issue open"
            exit 0
          fi

          body=$(printf '%s\n' \
            "The advisories check of cargo-deny fails on \`$LINE\` at \`$sha\`, on a lockfile resolved by the run (the library commits none). By graph (\`all\`: all features; \`wasm32\`: the Cloudflare slice; \`default\`: default features), the findings by kind:" \
            "" \
            "${findings%$'\n'}" \
            "" \
            "The run, with cargo-deny's full text: $run_url" \
            "" \
            "No pull request is blocked by this: a pull request's \`deny\` reads bans, licenses and sources. A release tag reads advisories too (\`release.yml\`'s \`advisories\` job, before \`publish\`), so this issue is closed before the next tag of \`$LINE\`, by a dependency change in a pull request of its own. Never by an entry in \`deny.toml\`'s ignore list, which stays empty (\`RELEASING.md\` step 2)." \
            "" \
            "This issue is rewritten by each daily run while the check fails and closed by the next clean run.")

          if [[ -n "$num" ]]; then
            gh api -X PATCH "repos/$GITHUB_REPOSITORY/issues/$num" --silent -f body="$body"
            echo "finding: rewrote issue $num"
          else
            gh api -X POST "repos/$GITHUB_REPOSITORY/issues" --silent -f title="$title" -f body="$body"
            echo "finding: opened an issue"
          fi
          printf '%s' "$findings"
"##;

/// `release.yml`'s `advisories` job, from its key's line to the line before the next job's key,
/// byte for byte (#1034's third fold). Any key added, removed or changed anywhere in the job
/// (at the job's level: `defaults`, `shell` under it, `env`, `if`, `continue-on-error`,
/// `container`, `services`, `strategy`, `uses`, `concurrency`, `environment`, `outputs`,
/// `timeout-minutes`; at a step's: `shell`, `working-directory`, `env`, `if`,
/// `continue-on-error`, `timeout-minutes`, `uses`, `with`; in any spelling, flow style, quoting
/// or indentation) fails by the job's line. The re-read of the two folds put
/// `defaults: {run: {shell: "true {0}"}}` after `runs-on:`, and `shell: "true {0}"` on the step,
/// and each passed the named rules of [`tag_errors`]. A deliberate change of the job moves this
/// constant in the same commit.
const ADVISORIES_JOB: &str = r##"  advisories:
    name: Advisories
    needs: version
    runs-on: ubuntu-latest
    # the daily run's shape and figure (advisories.yml: two jobs of about a minute, each
    # bounded at 15): a fetch of the database or the index that hangs ends the job, and the tag,
    # in 15 minutes, never at the runner's 6 hours (#1034's second fold)
    timeout-minutes: 15
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          persist-credentials: false

      - name: Install Rust
        uses: dtolnay/rust-toolchain@e2a55d2ffb04f378e9626c28d38b36d230d1e12f # v1
        with:
          toolchain: stable

      - name: Install cargo-deny 0.20.2
        uses: taiki-e/install-action@682ce6c3c696a4cd5168a05f98e51aa02b877941 # v2.89.1
        with:
          tool: cargo-deny@0.20.2

      - name: Resolve the lockfile
        run: cargo generate-lockfile

      - name: deny, all four checks
        run: |
          result=0
          cargo-deny --locked --all-features check advisories bans licenses sources || result=1
          cargo-deny --locked --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm" --target wasm32-unknown-unknown check advisories bans licenses sources || result=1
          cargo-deny --locked check advisories bans licenses sources || result=1
          exit "$result"

"##;

/// `release.yml`'s top-level keys, in order: each line at column 0 that is no comment and not
/// blank. `defaults`, `run-name` and `cache-mode` are absent, and so is a second document or a
/// key written twice; the three that reach every job, `permissions`, `concurrency` and `env`,
/// are [`RELEASE_INHERITS`] by value.
const RELEASE_TOP: [&str; 6] = [
    "name: Release",
    "on:",
    "permissions:",
    "concurrency:",
    "env:",
    "jobs:",
];

/// `release.yml` from its `permissions:` line to its `jobs:` line, byte for byte: what every
/// job of the tag inherits. A variable a shell reads at its start (`BASH_ENV`, `ENV`) put in the
/// workflow's `env:` makes every `run:` step of the `advisories` job run another script first.
const RELEASE_INHERITS: &str = "permissions:\n  contents: read\n\nconcurrency:\n  group: release-${{ github.ref }}\n  cancel-in-progress: false\n\nenv:\n  CARGO_TERM_COLOR: always\n\njobs:\n";

/// `release.yml`'s jobs, in order, each a key at two spaces written `  <id>:` once: a job id in
/// another spelling (quoted, in flow style, written twice) is no row of this list.
const RELEASE_JOBS: [&str; 11] = [
    "version",
    "ci",
    "docs",
    "msrv",
    "features",
    "machete",
    "advisories",
    "bench",
    "publish",
    "page",
    "front-pages",
];

/// The three graphs every `cargo-deny` site reads, by the arguments that select each:
/// all features, the Cloudflare slice on wasm32, default features.
const GRAPHS: [(&str, &str); 3] = [
    ("all features", " --all-features"),
    (
        "the wasm32 slice",
        " --no-default-features --features \"auth,wallet,transaction,overlay,socketio,wasm\" --target wasm32-unknown-unknown",
    ),
    ("default features", ""),
];

/// The version of cargo-deny every site installs, as `taiki-e/install-action` names it.
const TOOL: &str = "          tool: cargo-deny@0.20.2\n";

fn read(path: &str) -> String {
    std::fs::read_to_string(format!("{}/{path}", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_default()
        .replace("\r\n", "\n")
}

/// The block under a key at `depth` spaces, from its line to the next line at that depth
/// or shallower (blank lines and comments at any depth stay inside).
fn block<'a>(text: &'a str, depth: usize, key: &str) -> Option<&'a str> {
    let open = format!("{}{key}", " ".repeat(depth));
    let mut at = 0;
    let mut start = None;
    for line in text.split_inclusive('\n') {
        match start {
            None if line.trim_end() == open => start = Some(at),
            Some(from) => {
                let shallow = !line.trim().is_empty()
                    && !line.trim_start().starts_with('#')
                    && line.len() - line.trim_start().len() <= depth;
                if shallow {
                    return Some(&text[from..at]);
                }
            }
            None => {}
        }
        at += line.len();
    }
    start.map(|from| &text[from..])
}

/// The lines of a text that run cargo-deny, trimmed.
fn deny_lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| line.starts_with("cargo-deny "))
        .collect()
}

/// What a site no longer holds of "each graph once, on these checks, and nothing else".
fn graph_errors(site: &str, text: &str, before: &str, after: &str) -> Vec<String> {
    let lines = deny_lines(text);
    let mut errors = Vec::new();
    for (graph, arguments) in GRAPHS {
        let want = format!("cargo-deny{before}{arguments} {after}");
        if lines.iter().filter(|line| **line == want).count() != 1 {
            errors.push(format!("{site}: {graph} is not read once by `{want}`"));
        }
    }
    if lines.len() != GRAPHS.len() {
        errors.push(format!(
            "{site}: {} cargo-deny lines, not one a graph",
            lines.len()
        ));
    }
    errors
}

/// The `deny` step of ci.yml: from its `- name: deny` line to the next step.
fn deny_step(ci: &str) -> Option<&str> {
    let open = ci.find("      - name: deny\n        id: deny\n")?;
    let rest = &ci[open..];
    let end = rest[1..].find("\n      - ").map_or(rest.len(), |at| at + 2);
    Some(&rest[..end])
}

/// What the pull request's `deny` step no longer holds.
fn pull_request_errors(ci: &str) -> Vec<String> {
    let Some(step) = deny_step(ci) else {
        return vec![format!("{CI}: no `deny` step with the id `deny`")];
    };
    let mut errors = graph_errors(
        "ci.yml `deny`",
        step,
        " --locked",
        "check bans licenses sources || result=1",
    );
    if step.contains("advisories") {
        errors.push(
            "ci.yml `deny`: the step names `advisories`; a pull request is judged on its tree, and advisories are advisories.yml's and the tag's (#1034)".to_owned(),
        );
    }
    let trap = "          trap 'if [ $? -eq 0 ]; then echo \"PASS deny\"; else echo \"FAIL deny\"; fi' EXIT\n";
    if !step.contains(trap) {
        errors.push("ci.yml `deny`: the step's `PASS deny`/`FAIL deny` line is gone".to_owned());
    }
    if !step.trim_end().ends_with("          exit \"$result\"") {
        errors.push("ci.yml `deny`: the step does not end with `exit \"$result\"`".to_owned());
    }
    errors
}

/// The `uses:` lines of a workflow that are not pinned to a full commit sha.
fn unpinned(text: &str) -> Vec<&str> {
    text.lines()
        .filter_map(|line| line.trim().trim_start_matches("- ").strip_prefix("uses: "))
        .filter(|action| !action.starts_with("./"))
        .filter(|action| {
            let sha = action
                .split_once('@')
                .map_or("", |(_, rest)| rest.split(' ').next().unwrap_or(""));
            sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit())
        })
        .collect()
}

/// The lines of a workflow that hold a character a YAML reader can take for a line break or
/// that has no place in this file's text: any control character but the line feed (a carriage
/// return alone is a line break to YAML, so `# a comment\rdefaults: ...` is a comment to a line
/// reader and a key to GitHub's; a tab is never indentation), and U+0085, U+2028, U+2029 and
/// U+FEFF (line breaks to a YAML 1.1 reader, a byte-order mark inside the text). Read on the
/// text as `read` gives it, a CRLF pair already made LF.
fn stray_characters(file: &str, text: &str) -> Vec<String> {
    text.split('\n')
        .enumerate()
        .filter_map(|(at, line)| {
            line.chars()
                .find(|c| {
                    c.is_control() || matches!(c, '\u{85}' | '\u{2028}' | '\u{2029}' | '\u{feff}')
                })
                .map(|c| {
                    format!(
                        "{file} line {}: holds {:?}, {STRAY} or which has no place in a workflow's text",
                        at + 1,
                        c
                    )
                })
        })
        .collect()
}

/// The words of [`stray_characters`]' refusal, by which a plant written after a lone carriage
/// return or a NEL is refused ahead of the pin it would reach.
const STRAY: &str = "which a YAML reader can take for a line break";

/// The line `advisories.yml` opens with; above `on:` there is that line and comments and blank
/// lines alone.
const DAILY_NAME: &str = "name: advisories";

/// What `advisories.yml` holds above its `on:` line that is not its `name:` line, a comment or a
/// blank line. A key there (`defaults:`, `env:`, `run-name:`, a second `concurrency:`, a
/// document marker `---`, an anchor) reaches every job of the file, and `DAILY_PINNED` starts
/// at `on:`: the re-read of #1034's two folds put `defaults: {run: {shell: "true {0}"}}` on the
/// line of a comment, so every step ran as `true <script>`, green, and the suite passed.
/// Structure, not a list of keys: every line is the name, `#` at its column 0, or empty.
fn daily_head_errors(daily: &str) -> Vec<String> {
    let mut errors = stray_characters("advisories.yml", daily);
    let Some(open) = daily.find("\non:\n").map(|at| at + 1) else {
        return errors;
    };
    for (at, line) in daily[..open].lines().enumerate() {
        let allowed = if at == 0 {
            line == DAILY_NAME
        } else {
            line.is_empty() || line.starts_with('#')
        };
        if !allowed {
            errors.push(format!(
                "advisories.yml line {}: above `on:` the file holds `{DAILY_NAME}` as its opening line and comments and blank lines alone, not {line:?}",
                at + 1
            ));
        }
    }
    errors
}

/// The first line at which `advisories.yml`, from its `on:` line to its end, is not
/// [`DAILY_PINNED`], or `None` when it is the pin byte for byte: the file's line number, the
/// line pinned and the line found, each quoted so that a space shows.
fn daily_pin_error(daily: &str) -> Option<String> {
    let Some(open) = daily.find("\non:\n").map(|at| at + 1) else {
        return Some("advisories.yml: no `on:` line at a line's start".to_owned());
    };
    let body = &daily[open..];
    if body == DAILY_PINNED {
        return None;
    }
    let first = daily[..open].lines().count() + 1;
    let found: Vec<&str> = body.lines().collect();
    let expected: Vec<&str> = DAILY_PINNED.lines().collect();
    let at = found
        .iter()
        .zip(&expected)
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| found.len().min(expected.len()));
    let shown = |line: Option<&&str>| line.map_or("<end>".to_owned(), |line| format!("{line:?}"));
    Some(format!(
        "advisories.yml is not DAILY_PINNED byte for byte (a change to it is a change to this test in the same diff): advisories.yml line {}\n  expected: {}\n  found:    {}",
        first + at,
        shown(expected.get(at)),
        shown(found.get(at))
    ))
}

/// What the daily workflow no longer holds.
fn daily_errors(daily: &str, ci: &str) -> Vec<String> {
    if daily.is_empty() {
        return vec![format!(
            "{DAILY}: no such workflow; advisories are read once a day for each line (#1034)"
        )];
    }
    let mut errors = Vec::new();
    // the two events, and no other: a schedule and a dispatch
    let on = block(daily, 0, "on:").unwrap_or_default();
    let events: Vec<&str> = on
        .lines()
        .filter(|line| line.starts_with("  ") && !line.starts_with("   "))
        .map(str::trim)
        .collect();
    if events != ["schedule:", "workflow_dispatch:"] {
        errors.push(format!(
            "advisories.yml: its events are {events:?}, not a schedule and a dispatch alone"
        ));
    }
    if on.matches("- cron: ").count() != 1 {
        errors.push("advisories.yml: not one `cron` line: one run a day".to_owned());
    }
    // least permissions, stated once for the workflow and widened by no job
    let granted: Vec<&str> = block(daily, 0, "permissions:")
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .collect();
    if granted != ["permissions:", "  contents: read", "  issues: write"]
        || daily.matches("permissions:").count() != 1
    {
        errors.push(
            "advisories.yml: its permissions are not `contents: read` and `issues: write` alone, stated once".to_owned(),
        );
    }
    if daily.contains("secrets.") {
        errors.push(
            "advisories.yml: it names a secret; the workflow's own token is all it holds"
                .to_owned(),
        );
    }
    for action in unpinned(daily) {
        errors.push(format!(
            "advisories.yml: `{action}` is not pinned by a commit sha"
        ));
    }
    if daily.contains("continue-on-error") {
        errors.push("advisories.yml: it carries `continue-on-error`".to_owned());
    }
    // both lines from the one file a schedule reads (the default branch's)
    if !daily.contains("        line: [main, beta]\n") {
        errors.push("advisories.yml: the matrix is not `line: [main, beta]`".to_owned());
    }
    if daily.matches("          ref: ${{ matrix.line }}\n").count() != 1 {
        errors.push(
            "advisories.yml: the checkout does not take `ref: ${{ matrix.line }}`".to_owned(),
        );
    }
    // the three graphs, each to a log and a code of its own
    let lines = deny_lines(daily);
    for (graph, arguments) in GRAPHS {
        let want = format!("cargo-deny --color never --locked{arguments} check advisories > ");
        if lines.iter().filter(|line| line.starts_with(&want)).count() != 1 {
            errors.push(format!(
                "advisories.yml: {graph} is not read once by `{}`",
                want.trim_end_matches(" > ")
            ));
        }
    }
    if lines.len() != GRAPHS.len() {
        errors.push(format!(
            "advisories.yml: {} cargo-deny lines, not one a graph",
            lines.len()
        ));
    }
    // one issue a line, found by a fixed title
    if daily
        .matches("          title=\"advisories: $LINE\"\n")
        .count()
        != 1
    {
        errors.push("advisories.yml: the issue's title is not `advisories: $LINE`".to_owned());
    }
    for (what, call) in [
        (
            "opens the line's issue",
            "gh api -X POST \"repos/$GITHUB_REPOSITORY/issues\" ",
        ),
        (
            "rewrites the open issue",
            "gh api -X PATCH \"repos/$GITHUB_REPOSITORY/issues/$num\" ",
        ),
        (
            "closes it on a clean run",
            "gh api -X PATCH \"repos/$GITHUB_REPOSITORY/issues/$n\" --silent -f state=closed",
        ),
    ] {
        if daily.matches(call).count() != 1 {
            errors.push(format!("advisories.yml: no one line that {what}: `{call}`"));
        }
    }
    // the same pinned tool as the pull request's step
    if daily.matches(TOOL).count() != 1 || ci.matches(TOOL).count() != 1 {
        errors.push(format!(
            "advisories.yml and ci.yml do not each install `{}` once",
            TOOL.trim()
        ));
    }
    // and nothing else moved: the lines that decide what the run reports, and above them
    errors.extend(daily_pin_error(daily));
    errors.extend(daily_head_errors(daily));
    errors
}

/// The names in a job's `needs:`, list or scalar.
fn needs(job: &str) -> Vec<String> {
    job.lines()
        .find_map(|line| line.strip_prefix("    needs:"))
        .map(|value| {
            value
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .split(',')
                .map(|name| name.trim().to_owned())
                .filter(|name| !name.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// The first line at which `body`, found at `text[open..]`, is not `pinned`: the file's line
/// number, the line pinned and the line found, each quoted so that a space shows.
fn first_difference(file: &str, text: &str, open: usize, body: &str, pinned: &str) -> String {
    let first = text[..open].lines().count() + 1;
    let found: Vec<&str> = body.lines().collect();
    let expected: Vec<&str> = pinned.lines().collect();
    let at = found
        .iter()
        .zip(&expected)
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| found.len().min(expected.len()));
    let shown = |line: Option<&&str>| line.map_or("<end>".to_owned(), |line| format!("{line:?}"));
    format!(
        "{file} line {}\n  expected: {}\n  found:    {}",
        first + at,
        shown(expected.get(at)),
        shown(found.get(at))
    )
}

/// Whether a line of `release.yml` opens a job or a top-level key: two spaces and a character
/// that is no space and no `#`, or any character but a space and a `#` at column 0. A comment
/// or a blank line is neither, so either inside a job stays the job's.
fn opens_a_key(line: &str, depth: usize) -> bool {
    let rest = &line[line.len() - line.trim_start_matches(' ').len()..];
    let indent = line.len() - rest.len();
    indent <= depth && !rest.is_empty() && !rest.starts_with('#')
}

/// What `release.yml` no longer holds of the `advisories` job and of what every job inherits,
/// by structure (#1034's third fold): its top-level keys [`RELEASE_TOP`] and their three
/// inherited values [`RELEASE_INHERITS`], its jobs [`RELEASE_JOBS`] each once, and the job
/// [`ADVISORIES_JOB`] byte for byte, from its key to the next job's key.
fn release_shape_errors(release: &str) -> Vec<String> {
    let mut errors = stray_characters("release.yml", release);
    let top: Vec<&str> = release.lines().filter(|l| opens_a_key(l, 0)).collect();
    if top != RELEASE_TOP {
        errors.push(format!(
            "release.yml: its top-level keys are {top:?}, not {RELEASE_TOP:?}: a key there (`defaults`, `run-name`, a second document, a key written twice) reaches every job of the tag"
        ));
    }
    if release.matches(RELEASE_INHERITS).count() != 1
        || !release.contains(&format!("\n{RELEASE_INHERITS}"))
    {
        let open = release.find("\npermissions:\n").map_or(0, |at| at + 1);
        let end = release[open..]
            .find("\njobs:\n")
            .map_or(release.len(), |at| open + at + 7);
        errors.push(format!(
            "release.yml: what every job inherits is not RELEASE_INHERITS byte for byte: {}",
            first_difference(
                "release.yml",
                release,
                open,
                &release[open..end],
                RELEASE_INHERITS
            )
        ));
    }
    let jobs_open = release.find("\njobs:\n").map_or(release.len(), |at| at + 7);
    let jobs: Vec<&str> = release[jobs_open..]
        .lines()
        .filter(|l| opens_a_key(l, 2))
        .collect();
    let expected: Vec<String> = RELEASE_JOBS.iter().map(|id| format!("  {id}:")).collect();
    if jobs != expected {
        errors.push(format!(
            "release.yml: its jobs are {jobs:?}, not RELEASE_JOBS written `  <id>:` once each: a job id in another spelling or written twice may stand for `advisories`"
        ));
    }
    let Some(open) = release.find("\n  advisories:\n").map(|at| at + 1) else {
        return errors;
    };
    let mut end = release.len();
    let mut at = open + "  advisories:\n".len();
    for line in release[at..].split_inclusive('\n') {
        if opens_a_key(line.trim_end_matches('\n'), 2) {
            end = at;
            break;
        }
        at += line.len();
    }
    let body = &release[open..end];
    if body != ADVISORIES_JOB {
        errors.push(format!(
            "release.yml: the `advisories` job is not ADVISORIES_JOB byte for byte (a change to it is a change to this test in the same diff): {}",
            first_difference("release.yml", release, open, body, ADVISORIES_JOB)
        ));
    }
    errors
}

/// What the tag's path no longer holds.
fn tag_errors(release: &str) -> Vec<String> {
    let jobs = block(release, 0, "jobs:").unwrap_or_default();
    let Some(job) = block(jobs, 2, "advisories:") else {
        return vec![format!(
            "{RELEASE}: no `advisories` job; a tag reads all four checks before it publishes (#1034)"
        )];
    };
    let mut errors = graph_errors(
        "release.yml `advisories`",
        job,
        " --locked",
        "check advisories bans licenses sources || result=1",
    );
    if job.matches("\n    timeout-minutes: 15\n").count() != 1 {
        errors.push("release.yml `advisories`: no `timeout-minutes: 15` on the job; a gating job that hangs would hold the release for the runner's 6 hours (#1034's second fold)".to_owned());
    }
    if needs(job) != ["version"] {
        errors.push("release.yml `advisories`: the job is not behind the version job alone (`needs: version`)".to_owned());
    }
    let run_ends = job
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        == Some("          exit \"$result\"");
    if !run_ends || job.matches("result=0").count() != 1 {
        errors.push("release.yml `advisories`: the job does not end with `exit \"$result\"` over one `result=0`".to_owned());
    }
    for absorbed in ["continue-on-error", "    if:", "        if:", "|| true"] {
        if job.contains(absorbed) {
            errors.push(format!(
                "release.yml `advisories`: the job carries `{}`; it runs on every tag and none of its failures is absorbed",
                absorbed.trim()
            ));
        }
    }
    if job.matches(TOOL).count() != 1 {
        errors.push(format!(
            "release.yml `advisories`: it does not install `{}` once",
            TOOL.trim()
        ));
    }
    for action in unpinned(job) {
        errors.push(format!(
            "release.yml `advisories`: `{action}` is not pinned by a commit sha"
        ));
    }
    let publish = block(jobs, 2, "publish:").unwrap_or_default();
    if !needs(publish).iter().any(|name| name == "advisories") {
        errors.push("release.yml: `publish` does not wait for `advisories` (`needs:`); a version with an advisory nobody has looked at would be published (#1034)".to_owned());
    }
    if publish.contains("always()")
        || publish.contains("failure()")
        || publish.contains("cancelled()")
    {
        errors.push("release.yml: `publish` runs on a failed or cancelled `needs:`".to_owned());
    }
    // `publish`'s own keys, by name and order: a job-level `if:` that names `success()`
    // (`${{ success() || true }}`) runs the publish after a failed `advisories`, and the named
    // rule above reads three status functions alone (#1034's third fold)
    let keys: Vec<&str> = publish
        .lines()
        .skip(1)
        .filter(|line| opens_a_key(line, 4) && line.starts_with("    "))
        .map(|line| line.trim_start().split(':').next().unwrap_or_default())
        .collect();
    if keys != PUBLISH_KEYS {
        errors.push(format!(
            "release.yml: `publish`'s keys are {keys:?}, not {PUBLISH_KEYS:?}: a condition, a `continue-on-error` or a strategy on it can publish past a failed `advisories`"
        ));
    }
    errors.extend(release_shape_errors(release));
    errors
}

/// `publish`'s job-level keys, in order, each written plainly at four spaces.
const PUBLISH_KEYS: [&str; 5] = ["name", "needs", "runs-on", "permissions", "steps"];

/// What `deny.toml` no longer says of advisories: none is ignored.
fn deny_toml_errors(text: &str) -> Vec<String> {
    let section = text
        .find("[advisories]\n")
        .map(|at| {
            let rest = &text[at..];
            let end = rest[1..].find("\n[").map_or(rest.len(), |next| next + 1);
            &rest[..end]
        })
        .unwrap_or_default();
    let keys: Vec<&str> = section
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("ignore"))
        .collect();
    if keys == ["ignore = []"] {
        Vec::new()
    } else {
        vec![format!(
            "deny.toml: `[advisories]` does not hold `ignore = []` as its one ignore line ({keys:?}); a finding is answered by a dependency change, never an exemption (#1034)"
        )]
    }
}

fn assert_none(errors: &[String]) {
    assert!(
        errors.is_empty(),
        "{} refusals:\n{}",
        errors.len(),
        errors.join("\n")
    );
}

fn refused(errors: &[String], needle: &str) {
    assert!(
        errors.iter().any(|e| e.contains(needle)),
        "no `{needle}` in {errors:?}"
    );
}

#[test]
fn a_pull_requests_deny_step_reads_bans_licenses_and_sources_and_no_advisories_1034() {
    let ci = read(CI);
    assert_none(&pull_request_errors(&ci));

    // the step as it stood until #1034: all four checks on each graph
    let four = ci.replace(
        " check bans licenses sources || result=1\n",
        " check || result=1\n",
    );
    assert_ne!(four, ci);
    assert_eq!(
        pull_request_errors(&four).len(),
        3,
        "{:?}",
        pull_request_errors(&four)
    );
    // advisories named beside the three
    let named = ci.replace(
        " check bans licenses sources || result=1\n",
        " check advisories bans licenses sources || result=1\n",
    );
    refused(&pull_request_errors(&named), "names `advisories`");
    // a fourth cargo-deny line, a tag's branch among the step's lines
    let branch = ci.replacen(
        "          cargo-deny --locked check bans licenses sources || result=1\n",
        "          cargo-deny --locked check bans licenses sources || result=1\n          cargo-deny --locked check advisories || true\n",
        1,
    );
    let errors = pull_request_errors(&branch);
    refused(&errors, "4 cargo-deny lines");
    refused(&errors, "names `advisories`");
    // a graph dropped, a check dropped
    let two = ci.replacen(
        "          cargo-deny --locked --all-features check bans licenses sources || result=1\n",
        "",
        1,
    );
    refused(&pull_request_errors(&two), "all features is not read once");
    let fewer = ci.replacen(
        "--target wasm32-unknown-unknown check bans licenses sources",
        "--target wasm32-unknown-unknown check bans licenses",
        1,
    );
    refused(
        &pull_request_errors(&fewer),
        "the wasm32 slice is not read once",
    );
    // a failure absorbed
    let absorbed = ci.replacen(
        "          cargo-deny --locked check bans licenses sources || result=1\n",
        "          cargo-deny --locked check bans licenses sources || true\n",
        1,
    );
    refused(
        &pull_request_errors(&absorbed),
        "default features is not read once",
    );
    refused(
        &pull_request_errors(&ci.replace("echo \"FAIL deny\"", "echo \"PASS deny\"")),
        "`PASS deny`/`FAIL deny` line is gone",
    );
    refused(
        &pull_request_errors(&ci.replace("        id: deny\n", "        id: deny-gone\n")),
        "no `deny` step",
    );
}

#[test]
fn a_daily_workflow_reads_advisories_for_main_and_beta_on_the_three_graphs_1034() {
    let ci = read(CI);
    let daily = read(DAILY);
    assert_none(&daily_errors(&daily, &ci));

    refused(&daily_errors("", &ci), "no such workflow");
    let one = |old: &str, new: &str, needle: &str| {
        let text = daily.replacen(old, new, 1);
        assert_ne!(text, daily, "`{old}` is not in advisories.yml");
        refused(&daily_errors(&text, &ci), needle);
    };
    one(
        "  schedule:\n",
        "  push:\n",
        "not a schedule and a dispatch alone",
    );
    one(
        "  workflow_dispatch:\n",
        "  workflow_dispatch:\n  pull_request:\n",
        "not a schedule and a dispatch alone",
    );
    one(
        "  issues: write\n",
        "  issues: write\n  contents: write\n",
        "permissions are not",
    );
    one(
        "  contents: read\n  issues: write\n",
        "  contents: write\n  issues: write\n",
        "permissions are not",
    );
    one(
        "    runs-on:",
        "    permissions:\n      id-token: write\n    runs-on:",
        "permissions are not",
    );
    one(
        "          ref: ${{ matrix.line }}\n",
        "          ref: ${{ matrix.line }}\n          token: ${{ secrets.OTHER }}\n",
        "names a secret",
    );
    one(
        "        line: [main, beta]\n",
        "        line: [main]\n",
        "the matrix is not",
    );
    one(
        "          ref: ${{ matrix.line }}\n",
        "",
        "the checkout does not take",
    );
    one(
        " --all-features check advisories",
        " --all-features check bans",
        "all features is not read once",
    );
    one(
        "--target wasm32-unknown-unknown check advisories",
        "--target wasm32-unknown-unknown check",
        "the wasm32 slice is not read once",
    );
    one(
        "cargo-deny --color never --locked check advisories",
        "cargo-deny --color never check advisories",
        "default features is not read once",
    );
    one(
        "title=\"advisories: $LINE\"",
        "title=\"advisories $LINE $sha\"",
        "the issue's title is not",
    );
    one(
        "-f state=closed",
        "-f state=open",
        "closes it on a clean run",
    );
    one(
        TOOL,
        "          tool: cargo-deny@0.20.3\n",
        "do not each install",
    );
    let floating = daily.replacen("actions/checkout@", "actions/checkout@v4 # ", 1);
    refused(
        &daily_errors(&floating, &ci),
        "is not pinned by a commit sha",
    );
}

/// The changes that alter what the daily run reports without altering what it checks, each
/// passed by every named rule before #1034's fold: `(what, old, new)`, applied once.
const SILENCING: [(&str, &str, &str); 28] = [
    ("`set +e` dropped: the first failing graph stops the step, red with no issue", "          set +e\n", ""),
    ("the unjudged run's `exit 1` made `exit 0`: green on a graph not judged", "            exit 1\n          fi\n", "            exit 0\n          fi\n"),
    ("the issue step behind `if: false`", "      - name: Open, rewrite or close the line's issue\n", "      - name: Open, rewrite or close the line's issue\n        if: false\n"),
    ("the issue step behind an event condition never true", "      - name: Open, rewrite or close the line's issue\n", "      - name: Open, rewrite or close the line's issue\n        if: ${{ github.event_name == 'push' }}\n"),
    ("the exit code's check flipped", "[[ \"$code\" == \"0\" ]]", "[[ \"$code\" != \"0\" ]]"),
    ("the exit code's check dropped", "            if [[ \"$code\" == \"0\" ]]; then\n              continue\n            fi\n", ""),
    ("the findings branch flipped: a clean run opens, a finding closes", "if [[ -z \"$findings\" ]]; then", "if [[ -n \"$findings\" ]]; then"),
    ("the finding's pattern loosened off the line's start", "advisory='^error\\[(", "advisory='error\\[("),
    ("the fault check dropped: a config cargo-deny could not read taken for a finding", "if [[ -n \"$fault\" || -z \"$kinds\" ]]; then", "if [[ -z \"$kinds\" ]]; then"),
    ("the advisories step's `exit 0` made `exit 1`: the issue step skipped", "          exit 0\n\n      - name: Open", "          exit 1\n\n      - name: Open"),
    ("the clean run's `exit 0` removed: a clean run opens an issue", "            exit 0\n          fi\n\n          body=", "          fi\n\n          body="),
    ("`.pull_request == null` dropped: a pull request taken for the issue", ".pull_request == null and ", ""),
    ("`cancel-in-progress: true`", "  cancel-in-progress: false\n", "  cancel-in-progress: true\n"),
    ("`timeout-minutes` from 15 to 1", "    timeout-minutes: 15\n", "    timeout-minutes: 1\n"),
    ("`persist-credentials: true`", "          persist-credentials: false\n", "          persist-credentials: true\n"),
    ("`fail-fast: true`: one line's failure cancels the other's read", "      fail-fast: false\n", "      fail-fast: true\n"),
    ("two graphs written to one log", "check advisories > \"$RUNNER_TEMP/advisories-all.log\"", "check advisories > \"$RUNNER_TEMP/advisories-default.log\""),
    ("the lockfile step removed", "      - name: Resolve the lockfile\n        run: cargo generate-lockfile\n\n", ""),
    ("the kinds line's `|| true` removed", "sed 's/,/, /g' || true)", "sed 's/,/, /g')"),
    ("`LINE` fixed to `main`", "          LINE: ${{ matrix.line }}\n", "          LINE: main\n"),
    ("`--paginate` dropped: an issue past the first page opened twice", "gh api --paginate ", "gh api "),
    ("the issue picked by `tail`", "head -n 1)", "tail -n 1)"),
    ("`GH_TOKEN` removed", "          GH_TOKEN: ${{ github.token }}\n", ""),
    ("the issue step's loop drops the wasm32 graph", "          for graph in all wasm32 default; do\n            log=", "          for graph in all default; do\n            log="),
    ("the advisory id's pattern changed", "'ID: RUSTSEC-[0-9]{4}-[0-9]{4}'", "'ID: GHSA-[0-9]{4}-[0-9]{4}'"),
    ("the cron made monthly", "    - cron: \"23 6 * * *\"\n", "    - cron: \"23 6 1 * *\"\n"),
    ("an unjudged graph left unrecorded", "              unjudged=\"$unjudged $graph\"\n", ""),
    ("the step's log tail removed", "            tail -n 200 \"$RUNNER_TEMP/advisories-$graph.log\"\n", ""),
];

#[test]
fn a_change_that_silences_the_daily_alarm_is_refused_by_its_line_1034() {
    let ci = read(CI);
    let daily = read(DAILY);
    assert_eq!(daily_pin_error(&daily), None);
    let issue_step = "      - name: Open, rewrite or close the line's issue\n";
    let removed = daily
        .find(issue_step)
        .map(|at| format!("{}\n", daily[..at].trim_end()))
        .expect("the issue step");
    let mut plants: Vec<(&str, String)> = SILENCING
        .iter()
        .map(|(what, old, new)| {
            assert_eq!(
                daily.matches(old).count(),
                1,
                "`{old}` is not once in advisories.yml ({what})"
            );
            (*what, daily.replacen(old, new, 1))
        })
        .collect();
    plants.push(("the issue step removed", removed));
    for (what, text) in plants {
        // the first line the plant moved, read here from the two texts alone
        let at = daily
            .lines()
            .zip(text.lines())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| daily.lines().count().min(text.lines().count()));
        let line = format!("advisories.yml line {}\n", at + 1);
        let errors = daily_errors(&text, &ci);
        assert!(
            errors.iter().any(|e| e
                .starts_with("advisories.yml is not DAILY_PINNED byte for byte")
                && e.contains(&line)),
            "{what}: not refused by the pin at `{}`: {errors:?}",
            line.trim()
        );
    }
    // the header's prose above `on:` is free; a line of the pinned body is not, a comment included
    let prose = daily.replacen(
        "# The advisories run (#1034;",
        "# The advisories run (#1034,",
        1,
    );
    assert_ne!(prose, daily);
    assert_none(&daily_errors(&prose, &ci));
    let comment = daily.replacen(
        "# one run at a time, never cancelled",
        "# one run at a time",
        1,
    );
    refused(&daily_errors(&comment, &ci), "advisories.yml line 40\n");
    refused(
        &daily_errors(&daily.replacen("\non:\n", "\n\"on\":\n", 1), &ci),
        "no `on:` line",
    );
}

#[test]
fn a_tag_reads_all_four_checks_on_the_three_graphs_before_it_publishes_1034() {
    let release = read(RELEASE);
    assert_none(&tag_errors(&release));

    let one = |old: &str, new: &str, needle: &str| {
        let text = release.replacen(old, new, 1);
        assert_ne!(text, release, "`{old}` is not in release.yml");
        refused(&tag_errors(&text), needle);
    };
    one(
        "\n  advisories:\n",
        "\n  advisories-gone:\n",
        "no `advisories` job",
    );
    one(
        ", machete, advisories]\n",
        ", machete]\n",
        "`publish` does not wait for `advisories`",
    );
    one(
        " --all-features check advisories bans licenses sources",
        " --all-features check bans licenses sources",
        "all features is not read once",
    );
    one(
        "          cargo-deny --locked check advisories bans licenses sources || result=1\n",
        "          cargo-deny --locked check advisories bans licenses sources || true\n",
        "default features is not read once",
    );
    one(
        "          cargo-deny --locked check advisories bans licenses sources || result=1\n          exit \"$result\"\n",
        "          cargo-deny --locked check advisories bans licenses sources || result=1\n          exit 0\n",
        "does not end with `exit \"$result\"`",
    );
    one(
        "    name: Advisories\n    needs: version\n",
        "    name: Advisories\n",
        "not behind the version job alone",
    );
    one(
        "    timeout-minutes: 15\n    permissions:\n      contents: read\n    steps:\n",
        "    permissions:\n      contents: read\n    steps:\n",
        "no `timeout-minutes: 15` on the job",
    );
    one(
        "    timeout-minutes: 15\n    permissions:\n      contents: read\n    steps:\n",
        "    timeout-minutes: 360\n    permissions:\n      contents: read\n    steps:\n",
        "no `timeout-minutes: 15` on the job",
    );
    one(
        "    name: Advisories\n    needs: version\n",
        "    name: Advisories\n    needs: version\n    if: ${{ !contains(github.ref, '-beta.') }}\n",
        "the job carries `if:`",
    );
    one(
        "    name: Advisories\n    needs: version\n",
        "    name: Advisories\n    needs: version\n    continue-on-error: true\n",
        "the job carries `continue-on-error`",
    );
}

#[test]
fn deny_toml_ignores_no_advisory_1034() {
    let deny = read(DENY_TOML);
    assert_none(&deny_toml_errors(&deny));

    for (old, new) in [
        ("ignore = []\n", "ignore = [\"RUSTSEC-2026-0001\"]\n"),
        (
            "ignore = []\n",
            "ignore = [\n    { id = \"RUSTSEC-2026-0001\", reason = \"none\" },\n]\n",
        ),
        ("ignore = []\n", ""),
        ("ignore = []\n", "ignore = []\nignore-yanked = [\"x\"]\n"),
    ] {
        let text = deny.replacen(old, new, 1);
        assert_ne!(text, deny);
        refused(&deny_toml_errors(&text), "does not hold `ignore = []`");
    }
    // the list of another section is not this one's
    let moved = deny.replacen("ignore = []\n", "", 1) + "\n[other]\nignore = []\n";
    refused(&deny_toml_errors(&moved), "does not hold `ignore = []`");
}

/// `deny.toml` whole, byte for byte (#1034's fourth fold). Every table of it moves what the four
/// checks answer: `[advisories]` (`db-urls` pointed at another database, `yanked` and
/// `unmaintained` loosened, an `ignore`), `[graph]` (a crate `exclude`d, targets narrowed, a
/// table absent today and as able as any), `[bans]`, `[licenses]` and `[sources]`; the re-read
/// of the third fold found three changes that silence the daily alarm and the tag's gate and
/// passed every named rule. So the file is pinned whole, as `DAILY_PINNED` pins the daily
/// workflow: a deliberate change of `deny.toml` (a new parent of a banned crate, a license)
/// edits this text in the same diff, where a reviewer reads it. No tool of the repository
/// writes `deny.toml`.
const DENY_PINNED: &str = r##"# Adapted from bsv-stack-lean's paved-road policy for bsv-rs 0.8.2.
# cargo-deny 0.20.2; check normal, build and development dependencies.

# https://embarkstudios.github.io/cargo-deny/checks/advisories/cfg.html
[advisories]
db-urls = ["https://github.com/RustSec/advisory-db"]
yanked = "deny"
unmaintained = "all"
unsound = "all"
# Findings need their own dependency fix, never an exemption here.
ignore = []

# https://embarkstudios.github.io/cargo-deny/checks/bans/cfg.html
[bans]
# Report duplicates while ecosystem major versions coexist; do not skip them. A duplicate
# is refused beside this file, not in it: .github/scripts/duplicate_versions.py (the deny
# step of ci.yml) fails on one that docs/duplicate-versions.txt does not hold (#104).
multiple-versions = "warn"
multiple-versions-include-dev = true
wildcards = "deny"
# Only bsv-rs and the immediate parents in its graph may use these primitives.
# Re-read these parents when the dependency graph changes. No consumer-specific
# wrappers from the stack template belong in this crate's policy.
deny = [
    # bsv-rs 0.8.2 on the k256 0.14 line (#125): bsv-rs, k256 0.14.0 and p256 0.14.0.
    { name = "sha2", wrappers = ["bsv-rs", "k256", "p256"], reason = "Use bsv-rs hashing" },
    # bsv-rs 0.8.2: bsv-rs alone; secp256k1 is absent.
    { name = "ripemd", wrappers = ["bsv-rs"], reason = "Use bsv-rs hashing" },
    { name = "secp256k1", wrappers = ["bsv-rs"], reason = "Use bsv-rs keys and signatures" },
    { name = "k256", wrappers = ["bsv-rs"], reason = "Use bsv-rs keys and signatures" },
    { name = "bs58", wrappers = ["bsv-rs"], reason = "Use bsv-rs base58check" },
    # bsv-rs 0.8.2 on the k256 0.14 line (#125): bsv-rs, pbkdf2 0.13.0 and rfc6979 0.6.0.
    { name = "hmac", wrappers = ["bsv-rs", "pbkdf2", "rfc6979"], reason = "Use bsv-rs HMAC" },
    # bsv-rs 0.8.2: bsv-rs alone.
    { name = "p256", wrappers = ["bsv-rs"], reason = "Use bsv-rs keys and signatures" },
]

# https://embarkstudios.github.io/cargo-deny/checks/licenses/cfg.html
[licenses]
# Satisfies the resolved graph, including compound SPDX expressions.
allow = ["MIT", "Apache-2.0", "BSD-3-Clause", "Unicode-3.0"]
confidence-threshold = 0.9
include-dev = true
include-build = true

# https://embarkstudios.github.io/cargo-deny/checks/sources/cfg.html
[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
"##;

/// The files cargo-deny 0.20.2 reads beside `deny.toml` or in its place, from the manifest's
/// folder (`src/cargo-deny/common.rs:165-221`: the first of `deny.toml`, `.deny.toml`,
/// `.cargo/deny.toml`, and the license exceptions of `deny.exceptions.toml`,
/// `.deny.exceptions.toml`, `.cargo/deny.exceptions.toml`). Only `deny.toml` exists.
const OTHER_DENY_FILES: [&str; 5] = [
    ".deny.toml",
    ".cargo/deny.toml",
    "deny.exceptions.toml",
    ".deny.exceptions.toml",
    ".cargo/deny.exceptions.toml",
];

/// Where `deny.toml` is not [`DENY_PINNED`] byte for byte: its line, the line pinned and the
/// line found; and every other configuration file of cargo-deny that `root` holds.
fn deny_pin_errors(text: &str, present: &[&str]) -> Vec<String> {
    let mut errors: Vec<String> = present
        .iter()
        .map(|file| format!("{file}: a configuration file cargo-deny reads beside deny.toml or in its place; the configuration is deny.toml alone, pinned whole (#1034)"))
        .collect();
    if text != DENY_PINNED {
        let found: Vec<&str> = text.lines().collect();
        let expected: Vec<&str> = DENY_PINNED.lines().collect();
        let at = found
            .iter()
            .zip(&expected)
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| found.len().min(expected.len()));
        let shown =
            |line: Option<&&str>| line.map_or("<end>".to_owned(), |line| format!("{line:?}"));
        errors.push(format!(
            "deny.toml is not DENY_PINNED byte for byte (a change to it is a change to this test in the same diff): deny.toml line {}\n  expected: {}\n  found:    {}",
            at + 1,
            shown(expected.get(at)),
            shown(found.get(at))
        ));
    }
    errors
}

#[test]
fn deny_toml_is_pinned_whole_and_is_cargo_denys_one_configuration_1034() {
    let deny = read(DENY_TOML);
    let root = env!("CARGO_MANIFEST_DIR");
    let present: Vec<&str> = OTHER_DENY_FILES
        .iter()
        .copied()
        .filter(|file| std::path::Path::new(&format!("{root}/{file}")).exists())
        .collect();
    assert_none(&deny_pin_errors(&deny, &present));
    const PIN: &str = "deny.toml is not DENY_PINNED byte for byte";
    // the re-read's three, each silencing the daily alarm and the tag's gate
    for (old, new, line) in [
        (
            "[advisories]\n",
            "[graph]\nexclude = [\"slab\"]\n\n[advisories]\n",
            5,
        ),
        (
            "db-urls = [\"https://github.com/RustSec/advisory-db\"]\n",
            "db-urls = [\"https://example.invalid/advisory-db\"]\n",
            6,
        ),
        (
            "yanked = \"deny\"\nunmaintained = \"all\"\n",
            "yanked = \"allow\"\nunmaintained = \"none\"\n",
            7,
        ),
    ] {
        let text = deny.replacen(old, new, 1);
        assert_ne!(text, deny);
        let errors = deny_pin_errors(&text, &[]);
        refused(&errors, PIN);
        refused(&errors, &format!("deny.toml line {line}\n  expected"));
        // the older named rule reads none of them
        assert_none(&deny_toml_errors(&text));
    }
    // the same keys in another TOML spelling: a dotted key, an inline table, a quoted key
    for (old, new) in [
        (
            "unsound = \"all\"\n",
            "unsound = \"all\"\ngraph.exclude = [\"slab\"]\n",
        ),
        ("[bans]\n", "graph = { exclude = [\"slab\"] }\n\n[bans]\n"),
        ("yanked = \"deny\"", "\"yanked\" = \"allow\""),
        ("ignore = []\n", "ignore = [] # \n"),
        ("\n", "\r\n"),
    ] {
        let text = deny.replacen(old, new, 1);
        assert_ne!(text, deny);
        refused(&deny_pin_errors(&text, &[]), PIN);
    }
    refused(&deny_pin_errors(&format!("{deny}\n"), &[]), PIN);
    // a configuration beside it: the license exceptions file, or one cargo-deny reads in its
    // place when deny.toml is gone
    for file in OTHER_DENY_FILES {
        refused(
            &deny_pin_errors(&deny, &[file]),
            &format!("{file}: a configuration file"),
        );
    }
}

// The rules about OTHER workflows (a concurrency group shared with the daily run or the tag's, a
// reusable workflow called, a trigger by which one workflow reacts to another, a token's grant)
// are pinned sets over key paths since #1034's fifth fold: `arch_workflow_pinned_sets_1034.rs`.

/// Where a planted key sits: the file, the text it follows, the indentation it takes, and the
/// pin whose refusal names it.
struct Site {
    file: &'static str,
    after: &'static str,
    indent: &'static str,
    pin: &'static str,
}

const DAILY_HEAD: Site = Site {
    file: "advisories.yml",
    after: "name: advisories\n\n",
    indent: "",
    pin: "above `on:` the file holds `name: advisories`",
};
const DAILY_TOP: Site = Site {
    file: "advisories.yml",
    after: "  issues: write\n\n",
    indent: "",
    pin: "advisories.yml is not DAILY_PINNED byte for byte",
};
const DAILY_JOB: Site = Site {
    file: "advisories.yml",
    after: "    runs-on: ubuntu-latest\n",
    indent: "    ",
    pin: "advisories.yml is not DAILY_PINNED byte for byte",
};
const DAILY_STEP: Site = Site {
    file: "advisories.yml",
    after: "      - name: advisories\n",
    indent: "        ",
    pin: "advisories.yml is not DAILY_PINNED byte for byte",
};
const DAILY_ISSUE_STEP: Site = Site {
    file: "advisories.yml",
    after: "      - name: Open, rewrite or close the line's issue\n",
    indent: "        ",
    pin: "advisories.yml is not DAILY_PINNED byte for byte",
};
const RELEASE_TOP_SITE: Site = Site {
    file: "release.yml",
    after: "  CARGO_TERM_COLOR: always\n\n",
    indent: "",
    pin: "release.yml: its top-level keys are",
};
const RELEASE_JOB: Site = Site {
    file: "release.yml",
    after: "    needs: version\n    runs-on: ubuntu-latest\n",
    indent: "    ",
    pin: "release.yml: the `advisories` job is not ADVISORIES_JOB byte for byte",
};
const RELEASE_STEP: Site = Site {
    file: "release.yml",
    after: "      - name: deny, all four checks\n",
    indent: "        ",
    pin: "release.yml: the `advisories` job is not ADVISORIES_JOB byte for byte",
};

/// The keys of GitHub's workflow syntax (docs.github.com, "Workflow syntax for GitHub Actions",
/// read on 2026-11-17) at the three levels, each with a value that can make a failing step
/// pass, skip a step or a job, keep a job from running, or keep the alarm from opening its
/// issue, or that stands for any change of the key; and the YAML forms of a key that a line
/// reader can miss. `(level, line)`: the line is planted at each site of its level.
const TOP_KEYS: [&str; 8] = [
    "run-name: x",
    "permissions: {contents: read}",
    "env: {BASH_ENV: ./x}",
    "defaults: {run: {shell: \"true {0}\"}}",
    "concurrency: {group: x, cancel-in-progress: true}",
    "cache-mode: none",
    "jobs: {}",
    "on: {push: {branches: [x]}}",
];
const JOB_KEYS: [&str; 21] = [
    "name: x",
    "permissions: {contents: read}",
    "needs: [x]",
    "if: false",
    "runs-on: x",
    "snapshot: x",
    "environment: x",
    "concurrency: {group: x, cancel-in-progress: true}",
    "cache-mode: none",
    "outputs: {x: y}",
    "env: {BASH_ENV: ./x}",
    "defaults: {run: {shell: \"true {0}\"}}",
    "defaults: {run: {working-directory: /nonexistent}}",
    "timeout-minutes: 0",
    "strategy: {matrix: {line: []}}",
    "continue-on-error: true",
    "container: {image: x}",
    "services: {x: {image: y}}",
    "uses: ./.github/workflows/x.yml",
    "with: {x: y}",
    "secrets: inherit",
];
const STEP_KEYS: [&str; 15] = [
    "id: x",
    "if: false",
    "uses: ./x",
    "working-directory: /nonexistent",
    "shell: \"true {0}\"",
    "with: {x: y}",
    "env: {BASH_ENV: ./x}",
    "continue-on-error: true",
    "timeout-minutes: 0",
    "background: true",
    "wait: x",
    "wait-all: true",
    "cancel: x",
    "parallel: true",
    "name: x",
];

/// A key in the spellings a reader by line can miss: quoted, a space before the colon, in a
/// block, with a trailing comment, an anchor and a merge key, written after a lone carriage
/// return or a NEL inside a comment, led by a tab.
const SPELLINGS: [&str; 9] = [
    "\"defaults\": {run: {shell: \"true {0}\"}}",
    "defaults : {run: {shell: \"true {0}\"}}",
    "defaults:\n  run:\n    shell: \"true {0}\"",
    "defaults: {run: {shell: \"true {0}\"}} # a comment",
    "x: &x {run: {shell: \"true {0}\"}}\ndefaults: *x",
    "<<: {defaults: {run: {shell: \"true {0}\"}}}",
    "# a comment\rdefaults: {run: {shell: \"true {0}\"}}",
    "# a comment\u{85}defaults: {run: {shell: \"true {0}\"}}",
    "\tdefaults: {run: {shell: \"true {0}\"}}",
];

/// Every plant of the silencing class: `(site's name, what, the file's text planted)`.
fn silencing_plants(daily: &str, release: &str) -> Vec<(String, &'static Site, String)> {
    let mut plants = Vec::new();
    let mut plant = |name: &str, site: &'static Site, line: &str| {
        let text = if site.file == "advisories.yml" {
            daily
        } else {
            release
        };
        assert_eq!(
            text.matches(site.after).count(),
            1,
            "`{}` is not once in {}",
            site.after,
            site.file
        );
        let planted: String = line
            .split('\n')
            .map(|l| format!("{}{l}\n", site.indent))
            .collect();
        plants.push((
            format!("{name}: {line:?}"),
            site,
            text.replacen(site.after, &format!("{}{planted}", site.after), 1),
        ));
    };
    for (name, site) in [
        ("daily, above on:", &DAILY_HEAD),
        ("daily, top level below on:", &DAILY_TOP),
        ("release, top level", &RELEASE_TOP_SITE),
    ] {
        for line in TOP_KEYS.iter().chain(&SPELLINGS) {
            plant(name, site, line);
        }
        plant(name, site, "---");
        plant(name, site, "name: x");
    }
    for (name, site) in [
        ("daily, the job", &DAILY_JOB),
        ("release, the advisories job", &RELEASE_JOB),
    ] {
        for line in JOB_KEYS.iter().chain(&SPELLINGS) {
            plant(name, site, line);
        }
    }
    for (name, site) in [
        ("daily, the advisories step", &DAILY_STEP),
        ("daily, the issue step", &DAILY_ISSUE_STEP),
        ("release, the deny step", &RELEASE_STEP),
    ] {
        for line in STEP_KEYS.iter().chain(&SPELLINGS) {
            plant(name, site, line);
        }
    }
    plants
}

/// What the two checks answer on a plant: the daily file's or the tag's.
fn errors_of(site: &Site, text: &str, ci: &str) -> Vec<String> {
    if site.file == "advisories.yml" {
        daily_errors(text, ci)
    } else {
        tag_errors(text)
    }
}

#[test]
fn every_key_that_can_silence_the_alarm_or_the_tags_gate_is_refused_by_its_pin_1034() {
    let ci = read(CI);
    let daily = read(DAILY);
    let release = read(RELEASE);
    assert_none(&daily_errors(&daily, &ci));
    assert_none(&tag_errors(&release));
    let plants = silencing_plants(&daily, &release);
    assert_eq!(plants.len(), 3 * 19 + 2 * 30 + 3 * 24);
    let slipped: Vec<String> = plants
        .iter()
        .filter(|(_, site, text)| {
            !errors_of(site, text, &ci)
                .iter()
                .any(|e| e.contains(site.pin) || e.contains(STRAY))
        })
        .map(|(what, site, text)| {
            format!("{what} ({}): {:?}", site.file, errors_of(site, text, &ci))
        })
        .collect();
    assert!(
        slipped.is_empty(),
        "{} of {} plants not refused by their pin:\n{}",
        slipped.len(),
        plants.len(),
        slipped.join("\n")
    );

    // the re-read's two plants, as it wrote them: a comment line of the header replaced, and the
    // job's `defaults:` after `runs-on:` and the step's `shell:`
    let header = daily.replacen(
        "# This is the one workflow of the repository on a schedule",
        "defaults: {run: {shell: \"true {0}\"}}",
        1,
    );
    assert_ne!(header, daily);
    refused(
        &daily_errors(&header, &ci),
        "advisories.yml line 26: above `on:`",
    );
    for (old, new) in [
        ("    runs-on: ubuntu-latest\n    # the daily run's shape", "    runs-on: ubuntu-latest\n    defaults: {run: {shell: \"true {0}\"}}\n    # the daily run's shape"),
        ("      - name: deny, all four checks\n", "      - name: deny, all four checks\n        shell: \"true {0}\"\n"),
    ] {
        let text = release.replacen(old, new, 1);
        assert_ne!(text, release);
        refused(&tag_errors(&text), RELEASE_JOB.pin);
    }
    // a job written twice, in a second spelling, at the end of the jobs
    for twin in [
        "  \"advisories\":\n    runs-on: x\n",
        "  advisories: {runs-on: x}\n",
        "  advisories:\n    runs-on: x\n",
    ] {
        refused(
            &tag_errors(&format!("{release}{twin}")),
            "release.yml: its jobs are",
        );
    }
    // `publish` made to run past a failed `advisories` (c): a condition naming `success()`,
    // which the three status functions of the named rule do not read, in three spellings
    for planted in [
        "    if: ${{ success() || true }}\n",
        "    \"if\": ${{ success() || true }}\n",
        "    if : ${{ !success() || true }}\n",
    ] {
        let text = release.replacen(
            "    needs: [version, ci, docs, msrv, features, machete, advisories]\n",
            &format!(
                "    needs: [version, ci, docs, msrv, features, machete, advisories]\n{planted}"
            ),
            1,
        );
        assert_ne!(text, release);
        refused(&tag_errors(&text), "release.yml: `publish`'s keys are");
    }
    // what every job inherits, changed by value
    refused(
        &tag_errors(&release.replacen(
            "  CARGO_TERM_COLOR: always\n",
            "  CARGO_TERM_COLOR: always\n  BASH_ENV: ./x\n",
            1,
        )),
        "not RELEASE_INHERITS byte for byte",
    );
    refused(
        &tag_errors(&release.replacen(
            "  cancel-in-progress: false\n\nenv:",
            "  cancel-in-progress: true\n\nenv:",
            1,
        )),
        "not RELEASE_INHERITS byte for byte",
    );
    // a second document after the last job
    refused(
        &tag_errors(&format!("{release}---\njobs: {{}}\n")),
        "release.yml: its top-level keys are",
    );
    refused(
        &daily_errors(
            &format!("{daily}---\ndefaults: {{run: {{shell: \"true {{0}}\"}}}}\n"),
            &ci,
        ),
        DAILY_TOP.pin,
    );
}
