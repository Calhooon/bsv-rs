# Lane fix-1034-deny-shape: advisories leave the pull request's `deny` step (#1034)

Base `4c5454be` (`beta`, 2026-11-17). One commit. The decision and the scope are the issue's;
the shape is the stack's (`bsv-stack-lean` `template/` at `c27f2a63`, `advisories.yml` there
with sha256 `2de6c20a...391156a`; the ruling `docs/DECISIONS-2026-10-19.md` 27.5).

## What was taken from the template, and what was not

Taken: the split (a pull request reads `bans licenses sources`; advisories daily for each line
and on a tag); the daily workflow's events, permissions, concurrency group, matrix over `main`
and `beta`, and the issue script's logic (one issue a line by a fixed title, every page of the
open issues read, rewritten while the check fails, closed by a clean run with a comment, the
run red only when cargo-deny failed and named no finding).

Not taken, this repository's own:

| The template | Here | Why |
|---|---|---|
| a `deny` job, `--locked check` on one graph | the `deny` step of `lint`, three graphs | this repository's step (#79, #104) |
| all four checks in the same job when the ref is a tag | a job `advisories` of `release.yml`, `publish` waiting for it | the pull request's step then never names `advisories`, which the test can hold as text |
| cargo-deny by `curl` and a pinned sha256 | `taiki-e/install-action` at its pinned sha, `cargo-deny@0.20.2` | how `ci.yml` installs it |
| the committed lockfile | `cargo generate-lockfile` in the job | the library commits no lockfile |
| one log, one exit code | a log and a code a graph; a finding and a graph not judged in one run is red | three graphs |
| "does this line exist" step | none | both lines exist |
| the issue's triage: a lock move, a dependency change, a template entry | a dependency change alone | `deny.toml`'s ignore list stays empty |
| the runner comment | `ubuntu-latest`, as every workflow here | this repository's convention |

The repository had no scheduled workflow (the owner's words of 2026-10-27 on the nightly and
of 2026-11-10 on the front pages). This one is on a schedule by the ruling above, which is
later and the owner's; its header says so and states its load.

## RED

`tests/arch_advisories_1034.rs` on `4c5454be` with the file alone, 3 of 4:

- `a_pull_requests_deny_step_reads_bans_licenses_and_sources_and_no_advisories_1034`: three
  refusals, each graph `is not read once by cargo-deny --locked ... check bans licenses sources`;
- `a_daily_workflow_reads_advisories_for_main_and_beta_on_the_three_graphs_1034`:
  `.github/workflows/advisories.yml: no such workflow`;
- `a_tag_reads_all_four_checks_on_the_three_graphs_before_it_publishes_1034`:
  `.github/workflows/release.yml: no advisories job`;
- `deny_toml_ignores_no_advisory_1034` green there: an agreement pin, the list was empty.

## What a host could prove, and what it could not

| Path | Result |
|---|---|
| the three pull-request commands as written, on the tip | run: `bans ok, licenses ok, sources ok` three times, result 0 |
| `check advisories` on the three graphs, 2026-11-17 | run: `advisories ok` on each, exit 0 |
| `actionlint` on every workflow; `shellcheck` on the two scripts | run: clean |
| the daily check script on a finding | run: the step's text taken from the workflow's YAML and run in a stand-in crate (this `deny.toml`, `time =0.1.45` and `atty 0.2`): exit 1 a graph, `error[vulnerability]`, `error[unsound]`, `error[unmaintained]`, three `ID: RUSTSEC-...` lines a graph |
| the issue script: open | run against a stand-in `gh` (a script recording its arguments and holding the open numbers): one `POST .../issues` with the title and the body |
| the issue script: rewrite in place | run: with the issue open and one graph clean, one `PATCH .../issues/101` with the new body, no second issue |
| the issue script: close by a clean run | run: one comment and one `PATCH ... state=closed`; a clean run with nothing open makes the listing call alone |
| the issue script: could not judge | run: a graph failing with no `error[...]`, alone or beside a finding, and a missing code file: exit 1 and no call that writes |
| the listing's `--jq` filter | run as a GET on this repository: no number for `advisories: beta`, this issue's number for its own title |
| the schedule event | not run |
| the daily workflow on a hosted runner (the checkout of a line, the token's `issues: write`) | not run here; seen in `bsv-wallet-cli` with the template's file, not this one |
| the tag's job in `release.yml` | not run: a tag is the only way to start it; its three lines were run by hand (the two rows at the top) |

The stand-in `gh` does not apply `--jq` and does not page; the live GET above covers the
filter, nothing here covers a second page.

## The four sites of the required context

Nothing was renamed and no protection was changed.

| Site | `beta` | `main` |
|---|---|---|
| the workflow | `ci.yml`, job `lint`, step `deny` (id `deny`) | `ci.yml`, job `deny`, name `deny` |
| the protection (a GET, 2026-11-17) | five, `lint` among them, no `deny` | thirteen, `deny` among them |
| the architecture tests | `REQUIRED_ON_BETA` names `lint`; `BUNDLES` holds `("deny", "deny")` in `lint` | `REQUIRED_ON_MAIN` on `beta`'s tree names `lint` (the set after the promotion, by its own comment) |
| `RELEASING.md` step 2 | `lint` (Rustfmt, Clippy, deny, ratchet as steps) | thirteen with `deny`, then six |

## The pick to `main`

`main`'s tree differs where this commit lands, so the pick is a port, not a clean pick:

- `ci.yml`: `main` has a job `deny` whose step runs `"$RUNNER_TEMP/tools/bin/cargo-deny" --locked ... check`
  on the three graphs (cargo-deny built by `cargo install`); the three lines take
  `check bans licenses sources` there, and the test's `pull_request_errors` reads that job's
  form (no `id: deny` step, no `PASS deny` line, another binary path);
- `release.yml`: `main`'s `publish` holds the same `needs:` list, so the job and the list port
  as written; the job installs cargo-deny its own way (`taiki-e/install-action`), which `main`'s
  `ci.yml` does not use: the test's "same tool as `ci.yml`" rule compares the version there;
- `advisories.yml`: as written; it starts reading on the day it is on `main`;
- `tests/arch_duplicate_versions_104.rs`, `docs/ARCH-RULES.md`, `docs/ARCHITECTURE.md` and the
  rows script are not on `main`: their hunks drop; `tests/arch_ci_lines.rs`, `tests/CLAUDE.md`,
  `RELEASING.md`, `CHANGELOG.md` and the root `CLAUDE.md` differ and are ported by hand.

A workflow file reaching `main` is the direction rule's matter (`RELEASING.md`): the captain's.

## The fold: the daily run's script pinned line by line (lane fix-1034-deny-shape-fold)

The strength read of PR #1035 filed one row, classed after the cut and folded before the
landing by the captain's ruling: the daily workflow raises the alarm and gates nothing, and its
control flow was pinned by no test, so a change that silences the alarm (the advisories step's
`set +e` dropped, the unjudged run's `exit 1` made `exit 0`) passed the suite. The fold pins
`advisories.yml` from its `on:` line to its end byte for byte, `DAILY_PINNED` in
`tests/arch_advisories_1034.rs`, read through `daily_errors` beside the named rules, the form of
`SIBLING_JOB` (`tests/arch_ci_pr_runs_the_required_set.rs`): a failure names the line of
`advisories.yml`, the line pinned and the line found. The header's prose above `on:` is free; a
comment inside the body is pinned. A deliberate change of the workflow moves the pin in the same
commit.

The plants, each applied once to a scratch copy of `8f0b6e20`'s `advisories.yml`, every
`arch_*` binary run against it (the binaries read the file at run time, so one build served all):

| Plant | Caught before | Caught now |
|---|---|---|
| `set +e` dropped | no | yes |
| the unjudged run's `exit 1` made `exit 0` | no | yes |
| the issue step behind `if: false` | no | yes |
| the issue step behind an event condition never true | no | yes |
| the issue step removed | yes (the open, rewrite and close lines) | yes |
| the exit code's check flipped; dropped | no; no | yes; yes |
| the findings branch flipped | no | yes |
| the finding's pattern loosened off the line's start | no | yes |
| the advisories step's `exit 0` made `exit 1` (the issue step skipped) | no | yes |
| the clean run's `exit 0` removed (a clean run opens an issue) | no | yes |
| `.pull_request == null` dropped | no | yes |
| `cancel-in-progress: true`; `fail-fast: true` | no; no | yes; yes |
| `timeout-minutes` 15 to 1; `persist-credentials: true` | no; no | yes; yes |
| two graphs written to one log | no | yes |
| the lockfile step removed | no | yes |
| the kinds line's `\|\| true` removed | no | yes |
| `LINE` fixed to `main`; `GH_TOKEN` removed | no; no | yes; yes |
| `--paginate` dropped; the issue picked by `tail` | no; no | yes; yes |
| the issue step's loop drops the wasm32 graph | no | yes |
| the advisory id's pattern changed | no | yes |
| the cron made monthly | no | yes |
| an unjudged graph left unrecorded | no | yes |
| the advisories step's log tail removed | no | yes |

28 plants: 1 caught before, 28 now. The test
`a_change_that_silences_the_daily_alarm_is_refused_by_its_line_1034` carries the 28 and asserts
each refused by the pin at the line it moved (that line read from the two texts by the test
itself), the header's prose free, a comment of the body pinned, and an `on:` line spelled
otherwise refused. The pick to `main` carries the test's pin with the workflow, as written.

## The second fold: the daily run's three answers shown by runs of the pinned tool (lane fix-1034-deny-shape-fold2)

The captain's ruling: an alarm is finished when each of its three answers (clean, a finding,
could not judge) is shown by a run of the real tool, and a gating job cannot hang a release.

The tool: cargo-deny 0.20.2, the version both workflows pin, its release binary for
`aarch64-apple-darwin` (the one `taiki-e/install-action` fetches for Linux, built from the same
tag), its sha256 checked against the release's `.sha256`, installed in a scratch root outside
the host's cargo. A copy of the tip (`git archive` of `d1eaddb3`), a lockfile by
`cargo generate-lockfile`, then the advisories step's `run:` block and the issue step's decision
lines, both lifted from `advisories.yml` by a script and run as written with `$RUNNER_TEMP` a
folder of the state's own. No `gh` call was made.

| State | Exit (all, wasm32, default) | Branch until this fold | Branch it should take | Fixed |
|---|---|---|---|---|
| (a) the tree | 0, 0, 0 | clean | clean | not needed |
| (b) `deny.toml` with a syntax error (`[advisories` unclosed) | 1, 1, 1 | not judged (an `[ERROR] failed to parse config` line alone) | not judged | not needed |
| (c) `deny.toml` naming `not-a-key` in `[advisories]` | 1, 1, 1 | a finding: `unexpected-keys: 1; advisory ids: none named` on each graph (the issue opened, reading as an advisory) | not judged | yes |
| (d) the database at `https://advisory-db.invalid/...`, a fresh `db-path` | 1, 1, 1 | not judged (`[ERROR] failed to fetch advisory database`) | not judged | not needed |
| (e) the lock with `slab` moved to 0.4.10 (`cargo update -p slab --precise 0.4.10`) | 1, 1, 1 | a finding: `vulnerability: 1, yanked: 1; advisory ids: RUSTSEC-2025-0047` on each graph | a finding naming the id | not needed |
| (f) the tree on the toolchain 1.98.1, which has no `wasm32-unknown-unknown` installed (`RUSTUP_TOOLCHAIN`, `rustup target list --installed` naming the host alone) | 0, 0, 0 | clean (the wasm32 graph judged: `advisories ok`) | judged | not needed |
| (f) with (e)'s lock | 1, 1, 1 | a finding naming RUSTSEC-2025-0047 on the wasm32 graph too | a finding | not needed |

A first try at (d) with a `file://` URL was refused as a config (`advisory database url
doesn't have a domain name`), also not judged; the recorded (d) is the `.invalid` host, a fetch
that cannot answer. (f): cargo-deny filters the graph by the target's `cfg` without the
target's standard library, so the workflow installs no target and nothing moves.

The fix (c): a finding is an `error[...]` of an advisory's kind alone (`vulnerability`,
`notice`, `unmaintained`, `unsound`, `yanked`: the five codes of cargo-deny's advisories check
that report a crate; `index-failure` and the rest are faults), and a fault beside it (another
`error[...]`, a bare `error:`, cargo-deny's own `[ERROR]` log line) makes the graph not
judged. The `::error::` line now says `could not judge`.

The test's form: the decision lines run as a bash script over the recorded logs and codes, the
script lifted from the workflow's text at test time, so the test reads the workflow as it is.
`tests/data/advisories_1034/` holds each state's six files (the tree's and the database's
paths rewritten to a runner's). RED: on the fold's base 2 of 2 failing:
`each_recorded_answer_of_cargo_deny_takes_its_branch_1034` at `b_toml_syntax_error`, the earlier
state of its table, on the base's `::error::` words (`cargo-deny failed and named no finding on:
...`), and `a_config_cargo_deny_cannot_read_is_never_an_advisory_finding_1034` at
`c_unknown_advisories_key` (`Finding("- \`all\`: unexpected-keys: 1; ...")`) (corrected by the
third fold, run on `d1eaddb3`'s `advisories.yml` under the tip's test file; this paragraph named
`c_unknown_advisories_key` for both); with the
kinds widened and the `[ERROR]` pattern unread planted in `advisories.yml` itself, 2 of 2
failing by that state's name. The byte pin (`DAILY_PINNED`) moved in the same commit, the
silencing plants 28 (the pattern plant moved to the new line, the fault check's removal added),
the comment line of its prose test now line 40.

The tag's job: `timeout-minutes: 15`, the daily job's figure in the daily workflow's shape
(checkout, toolchain, the prebuilt tool, a lockfile, one database fetch, the four checks on
three graphs: about a minute; locally the three `check advisories` lines ran in under two
seconds), so a fetch that hangs ends the job in 15 minutes and not the runner's 6 hours. Pinned
in `tag_errors`; the line removed and set to 360 each refused by name. Other jobs `publish`
needs with no `timeout-minutes` (not changed): `version`; the calls (a caller of a reusable
workflow takes no `timeout-minutes`), whose called jobs carry none: `ci.yml`'s
`dependents-plan`, `dependent-check`, `dependents`, `semver`, `semver-tool-seed`, `test`,
`lint`, `checks`, `sibling`, `main-in-beta`, `beta-born`; `docs.yml`'s `actionlint`;
`msrv.yml`'s `msrv`; `features.yml`'s `features` and `wasm32-slices`; `machete.yml`'s
`machete`.

Not verified here: a hosted Linux runner (the binary was the macOS build of the same tag); an
`index-failure` answer (a registry index that cannot be fetched), read as not judged by the
rule and not recorded.

## The third fold (2026-11-17): the fixtures leave an owned folder; the class closed by structure

The re-read of the two folds (FIX 0.9) found the head red on two required checks and three
silencing changes that passed every test. Each is closed here as a class.

### Which test owns which folder

A test owns a folder when it fails on a file there that it does not expect. Read by a search of
every `read_dir`, `glob`, `iterdir`, `listdir` and `walk` under `tests/` and `.github/scripts/`,
each site read.

| test | folder | rule |
| --- | --- | --- |
| `fixtures_replay.rs` (`support/fixtures/mod.rs`) | `tests/fixtures/`, recursively | every file a `.json` and every file a recorded fixture: the set on disk equals the recorded set (`unexpected fixture ...`, `fixture file inventory changed`) |
| `arch_advisories_answers_1034.rs` | `tests/data/advisories_1034/` | every entry a state of its table, and every state on disk |
| `wallet_wire_cross_sdk_tests.rs` (two tests) | `tests/vectors/wallet_wire/` | every `*-args.json` is `ARGS_VECTORS`, every `*-result.json` `RESULT_VECTORS` |
| `readme_examples.rs` | `examples/` | every `*.rs` a README block, exactly once |
| `arch_ci_runs_every_test.rs` | `tests/*.rs` | every top-level binary run by a step of `ci.yml` on a feature set it compiles under |
| `arch_tests_claude_rows_name_modules_706.rs` | `tests/*.rs` | every top-level binary a row of `tests/CLAUDE.md` |
| `arch_fuzz_targets_dispatched.rs` | `fuzz/corpus/<target>/` | each target's folder holds a seed (a requirement on a folder, no refusal of a file) |
| `arch_door_says_what_spend_says_855.rs` | `src/script/spend/*.rs` | every public setter and `SpendParams` field has a counterpart on the door |
| `arch_text_doors.rs`, `arch_one_wallet_byte_bound.rs`, `arch_listed_spend_binds_its_input.rs`, `arch_support` (the `arch_no_*` family) | `src/` and its modules | rules over every source file |
| `arch_nightly_cap.rs`, `support/nightly_cap_rules.rs`, `arch_ci_sibling_judge_97.rs`, `arch_ci_called_jobs_stay_within_the_grant_909.rs`, `arch_ci_pr_runs_the_required_set.rs`, `front_page.rs`, `arch_advisories_1034.rs` (the concurrency-group rule) | `.github/workflows/*.yml` | rules over every workflow |
| `front_page.rs` | `.github/actions/`, `.github/scripts/` (less `fixtures/`) | a count of composite actions; a stored token in no script |

Walkers that read and skip what they cannot use own nothing: `beef_two_readers_agree.rs`,
`merkle_path_two_readers_agree.rs` (`.json` under `tests/fixtures/` and `tests/vectors/`),
`beef_merge_beef_txid_621.rs`, `support/beef_seeds_817.rs`, `merkle_path_writer_refusals_817.rs`
(their vector folders), `verify_input_door.rs` (every `.bin` under `tests/`). The Python tests
walk temporary folders of their own. Counts: 11 rows over 11 folders; six rows refuse a file
they do not expect by its name or kind (`fixtures_replay`, the answers test, the wire vectors,
the examples, the two rules over `tests/*.rs`), the others judge every file of their folder by
a rule (this fold's concurrency rule joins the workflows' row).

The fixtures move from `tests/fixtures/advisories_1034/` to `tests/data/advisories_1034/` (42
files, `git mv`): no test but their own takes an inventory of `tests/data/`
(`chain_primitives.rs` reads three named files there by `include_bytes!`), and `.gitattributes`
keeps `tests/data/**` byte for byte, as it kept `tests/fixtures/**`. `FIXTURES` and every record
follow (this file, `tests/CLAUDE.md`, `docs/ARCH-RULES.md`, the CHANGELOG entry).

### The silencing class

Read from GitHub's "Workflow syntax for GitHub Actions" (docs.github.com, fetched 2026-11-17):
the top-level keys `name`, `run-name`, `on`, `permissions`, `env`, `defaults`, `concurrency`,
`cache-mode`, `jobs`; under a job `name`, `permissions`, `needs`, `if`, `runs-on`, `snapshot`,
`environment`, `concurrency`, `cache-mode`, `outputs`, `env`, `defaults` (`run.shell`,
`run.working-directory`), `steps`, `timeout-minutes`, `strategy`, `continue-on-error`,
`container`, `services`, `uses`, `with`, `secrets`; under a step `id`, `if`, `name`, `uses`,
`run`, `working-directory`, `shell`, `with`, `env`, `continue-on-error`, `timeout-minutes`,
`background`, `wait`, `wait-all`, `cancel`, `parallel`. Each can make a failing step pass
(`shell: "true {0}"`, `continue-on-error`, `env: {BASH_ENV: ...}` a shell reads at start), skip
a step or a job (`if`, `needs`, an empty `strategy`), keep a job from running (`runs-on`,
`container`, `environment`, `snapshot`, `uses`), cancel it (`concurrency`, `timeout-minutes: 0`)
or keep the alarm from opening its issue (any of these on the issue step). Beside the keys: a key
quoted, with a space before its colon, in a block, with a trailing comment, an anchor and its
alias, a merge key, written after a lone carriage return or a NEL inside a comment (a line break
to YAML, none to a reader by `\n`), led by a tab, a second document (`---`), a key written
twice.

Each line below was planted at each site of its level (`silencing_plants`, the test
`every_key_that_can_silence_the_alarm_or_the_tags_gate_is_refused_by_its_pin_1034`): D is
`advisories.yml`, R `release.yml`; "top" the top level, "job" the `advisories` job, the steps
the advisories step and the issue step of the daily file and the deny step of the tag's job.
A cell is what `2ad25940`'s checks (`daily_errors`, `tag_errors`) answered: `passed` (no
refusal), `pin` (`DAILY_PINNED`), or the named rule that caught it. 189 plants: 87 passed.

| key planted (its line) | D above `on:` | D top, below `on:` | R top | D job | R job | D advisories step | D issue step | R step |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `run-name: x` | passed | pin | passed |  |  |  |  |  |
| `permissions: {contents: read}` | permissions rule | permissions rule | passed | permissions rule | passed |  |  |  |
| `env: {BASH_ENV: ./x}` | passed | pin | passed | pin | passed | pin | pin | passed |
| `defaults: {run: {shell: "true {0}"}}` | passed | pin | passed | pin | passed |  |  |  |
| `concurrency: {group: x, cancel-in-progress: true}` | passed | pin | passed | pin | passed |  |  |  |
| `cache-mode: none` | passed | pin | passed | pin | passed |  |  |  |
| `jobs: {}` | passed | pin | passed |  |  |  |  |  |
| `on: {push: {branches: [x]}}` | passed | pin | passed |  |  |  |  |  |
| `"defaults": {run: {shell: "true {0}"}}` | passed | pin | passed | pin | passed | pin | pin | passed |
| `defaults : {run: {shell: "true {0}"}}` | passed | pin | passed | pin | passed | pin | pin | passed |
| `defaults:\n  run:\n    shell: "true {0}\` | passed | pin | passed | pin | passed | pin | pin | passed |
| `defaults: {run: {shell: "true {0}"}} # a comment` | passed | pin | passed | pin | passed | pin | pin | passed |
| `x: &x {run: {shell: "true {0}"}}\ndefaults: *x` | passed | pin | passed | pin | passed | pin | pin | passed |
| `<<: {defaults: {run: {shell: "true {0}"}}}` | passed | pin | passed | pin | passed | pin | pin | passed |
| `# a comment\rdefaults: {run: {shell: "true {0}"}}` | passed | pin | passed | pin | passed | pin | pin | passed |
| `# a comment\u{85}defaults: {run: {shell: "true {0}"}}` | passed | pin | passed | pin | passed | pin | pin | passed |
| `\tdefaults: {run: {shell: "true {0}"}}` | passed | permissions rule | passed | pin | passed | pin | pin | passed |
| `---` | passed | pin | passed |  |  |  |  |  |
| `name: x` | passed | pin | passed | pin | passed | pin | pin | passed |
| `needs: [x]` |  |  |  | pin | passed |  |  |  |
| `if: false` |  |  |  | pin | `if:` rule | pin | pin | `if:` rule |
| `runs-on: x` |  |  |  | pin | passed |  |  |  |
| `snapshot: x` |  |  |  | pin | passed |  |  |  |
| `environment: x` |  |  |  | pin | passed |  |  |  |
| `outputs: {x: y}` |  |  |  | pin | passed |  |  |  |
| `defaults: {run: {working-directory: /nonexistent}}` |  |  |  | pin | passed |  |  |  |
| `timeout-minutes: 0` |  |  |  | pin | passed | pin | pin | passed |
| `strategy: {matrix: {line: []}}` |  |  |  | pin | passed |  |  |  |
| `continue-on-error: true` |  |  |  | `continue-on-error` rule | `continue-on-error` rule | `continue-on-error` rule | `continue-on-error` rule | `continue-on-error` rule |
| `container: {image: x}` |  |  |  | pin | passed |  |  |  |
| `services: {x: {image: y}}` |  |  |  | pin | passed |  |  |  |
| `uses: ./.github/workflows/x.yml` |  |  |  | pin | passed |  |  |  |
| `with: {x: y}` |  |  |  | pin | passed | pin | pin | passed |
| `secrets: inherit` |  |  |  | pin | passed |  |  |  |
| `id: x` |  |  |  |  |  | pin | pin | passed |
| `uses: ./x` |  |  |  |  |  | pin | pin | passed |
| `working-directory: /nonexistent` |  |  |  |  |  | pin | pin | passed |
| `shell: "true {0}\` |  |  |  |  |  | pin | pin | passed |
| `background: true` |  |  |  |  |  | pin | pin | passed |
| `wait: x` |  |  |  |  |  | pin | pin | passed |
| `wait-all: true` |  |  |  |  |  | pin | pin | passed |
| `cancel: x` |  |  |  |  |  | pin | pin | passed |
| `parallel: true` |  |  |  |  |  | pin | pin | passed |

On the tip every one of the 189 is refused by its pin, the test's assertion: above the daily
`on:` by `advisories.yml line N: above \`on:\` the file holds \`name: advisories\` as its opening
line and comments and blank lines alone, not ...`; below it by `advisories.yml is not
DAILY_PINNED byte for byte ...: advisories.yml line N`; at the tag's top level by
`release.yml: its top-level keys are [...]` (and `what every job inherits is not
RELEASE_INHERITS byte for byte` where the plant is inside it); in the tag's job and step by
`release.yml: the \`advisories\` job is not ADVISORIES_JOB byte for byte ...: release.yml line
N`; a plant after a lone CR or a NEL by `... holds '\r', which a YAML reader can take for a line
break ...` ahead of the pin. Rows the test plants beside the table: the re-read's three as
written (a comment line above `on:` replaced by `defaults:`; `defaults:` after the job's
`runs-on:`; `shell:` on the deny step); a twin `advisories` job (quoted, in flow style, plain,
after the last job: `release.yml: its jobs are ...`); `publish` under `if: ${{ success() ||
true }}` (plain, quoted, with a space before the colon: `release.yml: \`publish\`'s keys are
...`); `BASH_ENV` in the workflow's `env:` and `cancel-in-progress: true` in its concurrency
(`RELEASE_INHERITS`); a second document after the last job of either file; another workflow in
the group `advisories` (plain, quoted, in flow style) or `release-${{ github.ref }}`
(`no_other_workflow_shares_the_daily_or_the_tags_concurrency_group_1034`: `<file> line N: names
the concurrency group ...`).

`publish` still waits for the job (task (c)): `a_tag_reads_all_four_checks_on_the_three_graphs_before_it_publishes_1034`
plants `needs:` without `advisories` (`release.yml: \`publish\` does not wait for
\`advisories\``), and `PUBLISH_KEYS` now holds its keys: a condition naming `success()` passed the
named rule on `2ad25940` (one of this fold's own plants, found while trying to slip past (c)).

### Plants on the files, in a scratch root

The tip's `arch_advisories_1034.rs` and `2ad25940`'s, each compiled alone (`rustc --test`, the
file reads std alone) against a copy of `.github/workflows/` and `deny.toml`, twelve plants made
in the files one at a time (the script and its log under the lane's out folder):

| plant | `2ad25940` | tip |
| --- | --- | --- |
| the re-read's: a comment line above `on:` made `defaults: {run: {shell: "true {0}"}}` | 5 passed | 3 failed, `advisories.yml line 26: above \`on:\` ...` |
| the re-read's: `defaults:` after the tag job's `runs-on:` | 5 passed | 2 failed, `... not ADVISORIES_JOB byte for byte ...: release.yml line 205` |
| the re-read's: `shell: "true {0}"` on the deny step | 5 passed | 2 failed, `... release.yml line 230` |
| `env: {BASH_ENV: ./x}` as a new line above `on:` | 1 failed (the prose test's hard-coded `line 40`, by accident) | 3 failed, `advisories.yml line 2: above \`on:\` ...` |
| `defaults:` after a lone CR in a header comment | 1 failed (`line 40`, by accident) | 3 failed, `advisories.yml line 26: holds '\r' ...` |
| `defaults:` after a U+2028 in a header comment | 1 failed (`line 40`, by accident) | 3 failed, `... holds '\u{2028}' ...` |
| a top-level `defaults:` in `release.yml` | 5 passed | 2 failed, `release.yml: its top-level keys are ...` |
| `BASH_ENV` in `release.yml`'s `env:` | 5 passed | 2 failed, `... not RELEASE_INHERITS byte for byte: release.yml line 19` |
| `continue-on-error: true` at three spaces before `bench:` | 1 failed (`does not end with \`exit "$result"\``) | 2 failed, the same and `ADVISORIES_JOB` |
| a twin job as a complex key (`? advisories`) | 5 passed | 2 failed, `release.yml: its jobs are ...` |
| `publish` under `if: ${{ success() \|\| true }}` | 5 passed | 2 failed, `release.yml: \`publish\`'s keys are ...` |
| `concurrency: {group: advisories, cancel-in-progress: true}` in `docs.yml` | 5 passed | 1 failed, `docs.yml line 21: names the concurrency group "advisories" ...` |

### Two plants of my own per pin, to slip past it

- The daily header: a key after a lone CR in a comment, and after a U+2028 (a line reader sees a
  comment, GitHub's reader a key): both refused (`stray_characters`); a BOM before `name:` is
  the same rule's. A tab-led key: refused by the header rule and by `stray_characters`.
- `ADVISORIES_JOB`: a key at three spaces just before the next job (inside the job by
  indentation, past its last step) and a step key in flow style with a trailing comment: both
  inside the block the pin compares, refused by the job's line.
- `RELEASE_TOP`/`RELEASE_INHERITS`: a top-level key after a CR inside a comment (refused by
  `stray_characters`), `BASH_ENV` added to the `env:` block's indentation (refused by
  `RELEASE_INHERITS`).
- `RELEASE_JOBS`: the job written again as a complex key `? advisories` and as `"advisories":`:
  refused by the jobs' list.
- (c), `publish` waiting: `if: ${{ success() || true }}` on `publish` PASSED `2ad25940`'s
  rule, which read `always()`, `failure()` and `cancelled()` alone; fixed by `PUBLISH_KEYS`, the
  job's keys by name and order, in three spellings.
- The concurrency rule: the group in a flow mapping on one line (the reader looked at a line's
  head alone at first; fixed to read every `group:` of a line) and quoted: refused.

### Stated bounds

What these machines do not read, in plain words, as of the fourth fold: a concurrency group that
an expression builds from words that are not `advisories` or `release-`
(`${{ format('{0}{1}', 'advis', 'ories') }}`) in another workflow; a run cancelled or a workflow
disabled through the API or the repository's settings, by hand, by GitHub, or by a step of any
workflow that runs `gh run cancel` (a composite action under `.github/actions/` is such a step:
none exists, the style test does not walk that folder, and the daily file's and the tag job's
steps, pinned whole, call none); a change inside an action the steps call (each pinned by its
sha, so a change is a change of the pin's text); the toolchain `stable` and the runner image
moving under the jobs; another workflow file that reads advisories with the same name; a YAML
spelling that GitHub's own parser reads and libyaml does not (the differential's parser is
libyaml 0.2.5; the style test's refusals do not depend on any parser). `deny.toml` is pinned
whole since the fourth fold (`DENY_PINNED`), and the five files cargo-deny reads beside it or in
its place are refused. A deliberate change of either workflow or of `deny.toml` moves its pin
(`DAILY_PINNED`, `ADVISORIES_JOB`, `RELEASE_TOP`, `RELEASE_INHERITS`, `RELEASE_JOBS`,
`PUBLISH_KEYS`, `DENY_PINNED`) in the same commit; a new job of `release.yml` is a row of
`RELEASE_JOBS`.

### A record corrected

The paragraph above, `tests/CLAUDE.md`'s row and the CHANGELOG entry named
`c_unknown_advisories_key` as the RED of both answer tests on the fold's base. Run on
`d1eaddb3`'s `advisories.yml` under the tip's test file:
`each_recorded_answer_of_cargo_deny_takes_its_branch_1034` fails at `b_toml_syntax_error`, the
earlier state of its table (`exit Some(1): "::error::cargo-deny failed and named no finding on:
all wasm32 default. ..."`, the base's words), and
`a_config_cargo_deny_cannot_read_is_never_an_advisory_finding_1034` at
`c_unknown_advisories_key` (`left: Finding("- \`all\`: unexpected-keys: 1; ...")`).

## The fourth fold (2026-11-17): one plain style, `deny.toml` whole, a parser's differential (lane fix-1034-deny-shape-fold4)

The re-read of the third fold found four YAML spellings of the key `group` (a quoted key, a space
before the colon, a block scalar as the value, a quoted key in a flow mapping with the tag's
group) that the rule reading the text `group:` passed, and three changes to `deny.toml`
(`[graph] exclude = ["slab"]`, `db-urls` at another database, `yanked = "allow"` with
`unmaintained = "none"`) that silence both the daily alarm and the tag's gate and passed every
test. Each read of this pull request had found spellings its fold had not listed, so the class
is closed by two structures and a machine, not by a fourth list.

### The plain style

`tests/arch_workflow_plain_style_1034.rs` holds every file of `.github/workflows/` to one block
style in which a mapping key can be written in one way, so a reader of text sees every key a
YAML parser sees. The table below is every form of YAML 1.2's productions (and YAML 1.1's line
breaks) by which a key or its value can be written so that a reader of lines misreads it, and
the rule for each. No other YAML file is read by a workflow-reading test (the tests read the
files of `.github/workflows/` alone; the repository holds no other `.yml` under `.github/`).

| # | Form (production) | Rule |
|---|---|---|
| 1 | double-quoted key, `"k": v` (`c-double-quoted` as an implicit key) | nowhere |
| 2 | single-quoted key, `'k': v` (`c-single-quoted`) | nowhere |
| 3 | a space before the colon, `k : v` (`s-separate-in-line` before `c-mapping-value`) | nowhere |
| 4 | a tab before or after the colon, or as indentation | nowhere (any control character is refused) |
| 5 | a flow mapping holding a key, `{k: v}` (`c-flow-mapping`) | nowhere |
| 6 | the empty flow mapping `{}` | elsewhere: it holds no key |
| 7 | a flow sequence holding a mapping, `[k: v]`, `[{k: v}]` (`ns-flow-pair` in `c-flow-sequence`) | nowhere |
| 8 | a flow sequence of plain words (`[A-Za-z0-9_./*+-]`) or quoted scalars, closed on its line | elsewhere: an item of those holds no `:`, `{`, `[` or `?`, so it is no pair |
| 9 | a block scalar, `\|` or `>` with `-` or `+` (`c-l+literal`, `c-l+folded`) | only as the value of `run`, `script` (scripts), `if` (an expression), `path`, `restore-keys`, `sparse-checkout` (lists of paths for an action) and `VERDICTS` (an environment value of `ci.yml`): a body is text to the parser, so no key hides in it, and its body ends at the first line indented no deeper than its key |
| 10 | a block scalar with an indentation indicator, `\|2`, `>1-` | nowhere |
| 11 | a plain scalar over lines (`ns-plain-multi-line`) | nowhere: after a line with its value on it, the next line is no deeper than its key or its `- ` |
| 12 | a quoted scalar over lines | nowhere: a quoted scalar closes on its line |
| 13 | an escape in a double-quoted scalar, `"advisories"` | nowhere: a reader of the value would read other text |
| 14 | `''` in a single-quoted scalar | nowhere, for the same reason |
| 15 | an explicit key `? k` and its `: v` (`c-l-block-map-explicit-key`) | nowhere |
| 16 | an anchor `&x` (`c-ns-anchor-property`) | nowhere |
| 17 | an alias `*x` (`c-ns-alias-node`) | nowhere |
| 18 | a merge key `<<` (YAML 1.1's merge type) | nowhere: `<<` is no plain key name |
| 19 | a tag, `!!str k`, `!x`, `!<..>` (`c-ns-tag-property`) | nowhere |
| 20 | a second document, `---`, or a document end, `...` | nowhere |
| 21 | a directive, `%YAML`, `%TAG` | nowhere |
| 22 | a byte order mark, U+FEFF | nowhere |
| 23 | a line break other than LF: CR, CRLF, U+0085, U+2028, U+2029 (YAML 1.1's `b-char`) | nowhere |
| 24 | a non-ASCII space (U+00A0 and the rest) as indentation or in a key | nowhere: a key name is `[A-Za-z0-9_][A-Za-z0-9_.-]*`, a line led by one is no key line |
| 25 | any other control character | nowhere |
| 26 | a key twice in one mapping | nowhere: a parser keeps the later, a reader the earlier |
| 27 | a sequence in a sequence on one line, `- - x`, or an empty item `-` | nowhere |
| 28 | a plain scalar holding `: ` or ending in `:` | nowhere |
| 29 | a plain scalar opening with an indicator (`,[]{}#&*!\|>'"%@` or a backtick, `?`, `:`, `- `) | nowhere |
| 30 | a key whose name is outside `[A-Za-z0-9_][A-Za-z0-9_.-]*` | nowhere |
| 31 | a comment that looks like a key, `# defaults: x` | elsewhere: no parser reads it, and a reader of keys reads a key from its line's indentation, never inside a comment (a reader matching text anywhere refuses more, never less) |
| 32 | a trailing comment after a value, `v # c` | elsewhere: the value is read to ` #` |
| 33 | a line indented off the structure (a key deeper than its mapping, not after an opener) | elsewhere: it is no YAML, refused by the parser and by GitHub (rule 11 refuses the case a parser reads) |

33 rows: 27 allowed nowhere, 1 for the script and prose keys named in row 9, 5 elsewhere.
Today's breaches: none. Every block scalar of the 13 files is the value of a key of row 9, and no
other form of the table appears, so no file is rewritten and no parsed structure needed a
before-and-after comparison. In its place the style reader is compared with the parser on the
files as they stand: Psych 5.3.1 (libyaml 0.2.5, Ruby 4.0.9; this host has no PyYAML) reads
1,597 mapping keys in the 13 workflows, and the style's reader of key lines (outside the block
scalars' bodies) reads the same 1,597, each at the same line and column with the same name, and
no other (`keys_agree.rb` under the lane's logs). The test refuses 29 planted forms by line, the
re-read's four spellings and two more in `docs.yml` at its concurrency block, and five entries
of the folder that are not `.yml` or `.yaml` files (`x.YML`, `x.yml.disabled`, `x.json`, a folder
`sub`, a folder `x.yml`). `foreign_group_errors` (replaced by the fifth fold's pinned sets) read a key by its text as the style writes
it, which is sound because of the style: `group: <name>` and the short form `concurrency: <name>`,
a name holding `advisories` or `release-` refused outside its file, and a job calling another
repository's reusable workflow refused.

### `deny.toml` whole

`DENY_PINNED` in `tests/arch_advisories_1034.rs` is `deny.toml` byte for byte; a failure names its
line, the line pinned and the line found. A deliberate change of `deny.toml` (a new parent of a
banned crate, a license) edits `DENY_PINNED` in the same commit. No tool of the repository writes
the file (`duplicate_versions.py` and `arch_duplicate_versions_104.rs` read it), so the pin fights
nothing. Beside it, the five files cargo-deny 0.20.2 reads beside `deny.toml` or in its place
(`src/cargo-deny/common.rs:165-221`: `.deny.toml`, `.cargo/deny.toml`, and the license
exceptions of `deny.exceptions.toml`, `.deny.exceptions.toml`, `.cargo/deny.exceptions.toml`)
are refused by name. The re-read's three changes are RED by their line (5, 6, 7) and still pass
the older named rule (`deny_toml_errors`), which stays.

### The differential

Kept under the lane's logs (`/Volumes/Lanes/out/bsv-rs/fix-1034-deny-shape-fold4/differential/`:
`run.sh`, `respell.rb`, `harness_tail.rs`, `keys_agree.rb`), not under `.github/scripts/`: it needs
Ruby and a `rustc` build of the two test files with a harness appended, no CI job would run it, and
a script nothing runs goes stale; what CI holds is the style test and the pins, and the
differential is the proof that they suffice, run once on this tree. `run.sh <root>` builds the
harness (the tree's two test files as modules, the tail appended), dumps the plants (the third
fold's 189 from its own constants and sites, the re-read's four in `docs.yml`, two of this fold's),
respells each with libyaml's emitter in every style it offers (block and flow mappings and
sequences, plain, single-quoted, double-quoted, literal and folded scalars, keys plain, single or
double quoted, with and without `!!str` and `!!map` tags, indentation 2 and 4, line widths 80 and
unbounded; and the explicit-key form, written by hand: libyaml writes `?` only for a key that is
not simple), splices each into a copy of its file, and asks of each copy whether the parser sees
the plant (its documents differ from the unplanted file's and equal those of the plant's block,
plain spelling) and whether the tree's machines refuse it (the style, the daily file's and the
tag's checks, the concurrency rule). The same is asked of equivalents: the daily file and
`release.yml` respelled whole, the tag's `advisories` job, and each step of the daily job, with
nothing planted (seen when their documents equal the file's).

| | copies | the parser sees the plant or the equivalent | refused | difference |
|---|---:|---:|---:|---:|
| the 195 plants as written | 195 | 164 | 164 | 0 |
| respelled plants | 13,199 | 7,728 | 7,728 | 0 |
| equivalents | 1,902 | 719 | 719 | 0 |
| all | 15,296 | 8,611 | 8,611 | 0 |

Of the 8,611: 8,003 refused by the style, 594 by a pin (509 respelled plants and 65 plants in the
plain style, 20 equivalents), 14 by the concurrency rule. Of the 6,685 copies the parser does not
read as the plant (it refuses the text, the plant changes nothing, or a quoted value is another
type), all but three are refused too; the three are the plant `---` respelled, an empty document
the emitter writes as nothing, a copy of the unplanted file. The run takes about 11 seconds on
this host (7 to respell, 3 to judge). For `deny.toml` (no YAML) the re-read's three and five more
TOML spellings (a dotted `graph.exclude`, an inline `graph = { .. }`, `[graph] targets`, a quoted
`'yanked'`, a quoted table name) are refused by the pin; seven of the eight pass the named rule.

### Plants of my own, two per machine

- The concurrency rule: the short form `concurrency: advisories` in a job of `msrv.yml`, and
  `concurrency: release-x` at `machete.yml`'s top level, passed `bba84565`'s reader of `group:`;
  refused now. A job of `docs.yml` calling `someone/else/.github/workflows/x.yml@<sha>`, whose
  own concurrency no test reads, passed; refused now. `group: ${{ 'advisories' }}` passed (the
  reader took text opening `advisories`); refused now, a group's text read for `advisories` or
  `release-` anywhere in it.
- The style rule: a workflow under `.YML` or `.yml.disabled`, and one in a folder under
  `.github/workflows/`, are refused by name (the style reads `.yml` and `.yaml` files alone, so an
  entry the runner might read under another name is refused rather than left unread). A key in a
  composite action under `.github/actions/`, which the test does not walk: stated above (none
  exists; an action can cancel a run only through the API).
- `deny.toml`: a `deny.exceptions.toml` beside it (license exceptions cargo-deny reads from the
  manifest's folder) passed every test; refused now, with the other four such files. A dotted
  `graph.exclude` under `[advisories]` changes the table it reads as; refused by the pin.

## The fifth fold (2026-11-17): the rules about other workflows are pinned sets over key paths (lane fix-1034-deny-shape-fold5)

The re-read of the fourth fold found two rules about other workflows that compared text and
missed what the platform treats as the same thing: a concurrency group's name compared with its
case (`concurrency: Advisories` in a job of `msrv.yml`, and `group: Release-x-msrv-...` at its
top, passed every test), and a job calling another repository's reusable workflow seen at
indentation 4 alone (`  other:\n      uses: someone/else/...` in `docs.yml` passed). Four folds
had each closed the comparisons the read before had broken, so the captain's ruling replaces the
comparisons by two structures: a reader of key paths made sound by the style, and pinned sets.

### The keys that reach the alarm from another file

Read on 2026-11-17 from GitHub's documents. The pages: (W) "Workflow syntax for GitHub Actions",
`docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax`; (C) "Control the
concurrency of workflows and jobs", `.../how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency`;
(R) "Reuse workflows", `.../how-tos/reuse-automations/reuse-workflows`; (E) "Events that trigger
workflows", `.../reference/workflows-and-actions/events-that-trigger-workflows`; (A) the REST
pages "Workflow runs" and "Workflows", `docs.github.com/en/rest/actions/...`, and "Permissions
required for fine-grained personal access tokens". The page on automatic token authentication
answered 404 that day and is not cited.

| # | Key | What the documents say | Here |
|---|---|---|---|
| 1 | `concurrency` at a workflow's top level | (C) "You can also specify `concurrency` at the workflow level."; (C) "if another job or workflow using the same concurrency group in the repository is in progress, the queued job or workflow will be `pending`" | pinned as a set: `GROUPS` |
| 2 | `jobs.<id>.concurrency` | (W) "You can use `jobs.<job_id>.concurrency` to ensure that only a single job or workflow ..." | pinned as a set: `GROUPS` |
| 3 | a group's name, its case | (C) "The concurrency group name is case insensitive." and "`prod` and `Prod` will be treated as the same concurrency group." | `GROUPS` compares a name folded for case outside `${{ ... }}` |
| 4 | a group's name, an expression | (C) "A concurrency group can be any string or expression." (contexts `github`, `inputs`, `vars`, `needs`, `strategy`, `matrix`; (W) names `github`, `inputs`, `vars`) | `GROUPS` pins the expression as its text; `no_two_files_groups_can_meet_whatever_their_expressions_give_1034` holds that every group opens with a literal of its own that no other file's group opens with, so no value an expression gives makes two files' groups one |
| 5 | `cancel-in-progress`, `queue` | (C) "To also cancel any currently running job or workflow in the same concurrency group, specify `cancel-in-progress: true`."; (C) "The combination of `queue: max` and `cancel-in-progress: true` is not allowed" | pinned as a set: `GROUPS` (every pair under a `concurrency` key) |
| 6 | `jobs.<id>.uses`, this repository's | (R) "`./.github/workflows/{filename}` for reusable workflows in the same repository." | pinned as a set: `CALLS`; the called file's own keys are read with that file |
| 7 | `jobs.<id>.uses`, another repository's | (R) "`{owner}/{repo}/.github/workflows/{filename}@{ref}` for reusable workflows in public and private repositories." | pinned as a set: `CALLS` (none today); the called file's content is a stated bound (8 below) |
| 8 | what a called workflow may do | (R) "permissions can only be maintained or reduced" (and "not elevated") "throughout the chain."; (R) "Secrets are only passed to directly called workflow" | this repository's called files: inside the sets, read with their files, and `arch_ci_called_jobs_stay_within_the_grant_909.rs`; another repository's: a stated bound (no file of it is in this tree) |
| 9 | `jobs.<id>.secrets` | (R) "can use the `inherit` keyword to implicitly pass the secrets" | pinned as a set: `CALLS` |
| 10 | `cache-mode` | (R) "An explicit `cache-mode` on the calling job, or inherited from the caller workflow, limits the cache access the called workflow can request." | pinned as a set: `CALLS` (none today) |
| 11 | `on.workflow_run` | (W) "When using the `workflow_run` event, you can specify which workflows can trigger your workflow." | pinned as a set: `TRIGGERS` (every file's events, and every pair under the event but a `description`) |
| 12 | `on.workflow_call` | (W) "Use `on.workflow_call` to define the inputs and outputs for a reusable workflow." | pinned as a set: `TRIGGERS` |
| 13 | `on.workflow_dispatch` | (A) "You can use this endpoint to manually trigger a GitHub Actions workflow run." | pinned as a set: `TRIGGERS` |
| 14 | `on.repository_dispatch` | (E) "You can use the GitHub API to trigger a webhook event called `repository_dispatch`" | pinned as a set: `TRIGGERS` (none today) |
| 15 | an event the token raises | (E) "With the exception of `workflow_dispatch` and `repository_dispatch`," "other `GITHUB_TOKEN`-triggered events do not create workflow runs at all." | inside `TRIGGERS` (the two kinds that do are rows 13 and 14) |
| 16 | `actions: write` | (W) "`actions: write` permits an action to cancel a workflow run."; (A) cancel, re-run and disable: "write" in the fine-grained table (`POST .../runs/{run_id}/cancel`, `.../rerun`, `PUT .../workflows/{workflow_id}/disable`) | pinned as a set: `PERMISSIONS` (every grant, top level and job), and each job holding it pinned whole: `HOLDERS` |
| 17 | `issues: write` | (W) "`issues: write` permits an action to add a comment to an issue." | pinned as a set: `PERMISSIONS`, `HOLDERS` |
| 18 | a job that states no permissions | (W) "are initially set to the default setting for the enterprise, organization, or repository."; "all of those that are not specified are set to `none`" | `PERMISSIONS` holds each such job as a row `the repository's default` (none today); the setting itself a stated bound |
| 19 | a secret or the job's token in an expression | (R), (E): a token's scope is not in the file | pinned as a set since the sixth fold: `EXPRESSIONS`, every expression of every workflow (file, path, text), and each job holding a row of `SECRETS`, chosen by hand, pinned whole: `HOLDERS` (until the sixth fold `TOKENS`, chosen by three spellings) |
| 20 | a run cancelled or a workflow disabled by hand, in the settings, or by a personal token outside the repository | (A) "Disables a workflow and sets the state of the workflow to disabled_manually." | a stated bound: no file shows it |
| 21 | a composite action under `.github/actions/` | (none read) | a stated bound: none exists, and the steps of the two pinned blocks call none |

21 rows: 17 pinned as a set (1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 16, 17, 18, 19), 1 inside
the sets and a whole pin (15; 8's own half, this repository's called files, with them), 3 stated
bounds (8's other half, 20, 21).

### The indentation fixed, and the path reader

Measured with Psych on the 13 files: every block mapping is two spaces past its key (331), every
block sequence two spaces past its key (42), none at its key's column. The style now holds that
(`INDENT`, `support/workflow_style.rs`): a block opened under a key at its column plus two, one
space after a `- `, every other line at the column of a block still open, each breach refused by
file and line (`a_block_indented_other_than_two_spaces_past_its_key_is_refused_1034`: the
re-read's call at indentation 6, a block at 1, 0 and 6 spaces, three spaces after a dash, a line
at no open column, a file opening at column 1, `workflow_dispatch:` at 4; a block scalar's body
takes any depth past its key). The style code moved to `tests/support/workflow_style.rs`, shared
by the style test and the sets test.

`key_paths` reads every key's whole path and its scalar value (`jobs/<id>/steps/[i]/run` and the
script, a literal body kept and a folded one folded, `{}`, `[]`, a key with no value the empty
text), by structure: the column each block opens at, so a block at any indentation is read as a
parser reads it. On the 13 files it gives 1,270 pairs and Psych (5.3.1 over libyaml 0.2.5, the
same walk, `paths.rb` under the lane's logs) gives the same 1,270, in the same order, byte for
byte; on the 1,257 respelled copies of the differential that the style lets through and the
parser reads, the reader's pairs equal Psych's on all 1,257.

### The pinned sets

`tests/arch_workflow_pinned_sets_1034.rs` reads every workflow through `key_paths` and pins six
sets, each its complete rows in the repository today; a row added, removed or changed fails by
the set's name, and a deliberate change edits the set in the same commit.

| Set | Rows | What a row is |
|---|---:|---|
| `GROUPS` | 24 | every pair under a `concurrency` key (12 groups, 12 `cancel-in-progress`), a group's name folded for case outside its expressions |
| `CALLS` | 8 | `jobs/<id>/uses` (6, all `release.yml`'s of this repository), `jobs/<id>/secrets/...` (2), any `cache-mode` (0) |
| `TRIGGERS` | 45 | every file's events (25) and every pair under `workflow_run`, `workflow_call`, `workflow_dispatch`, `repository_dispatch` but a `description` |
| `PERMISSIONS` | 54 | every grant at a workflow's top level or a job's; a job taking the repository's default (0) |
| `TOKENS` | 26 | every `${{ ... }}` naming `secrets.` or `github.token`, by file and job (removed by the sixth fold: `EXPRESSIONS`) |
| `HOLDERS` | 12 | each job holding `actions: write`, `issues: write`, `write-all` or (since the sixth fold) a row of `SECRETS`, by an FNV-1a digest of its pairs |

RED by the pin's name (`the_re_reads_two_plants_are_refused_by_their_pins_1034`,
`each_kind_of_change_is_refused_by_its_pin_in_any_file_and_at_any_level_1034`): the re-read's
two (`concurrency: Advisories` in a job of `msrv.yml` and `Release-x-msrv-` at its top, by
`GROUPS`; `docs.yml`'s call at indentation 6 by `CALLS`, and by the style); in each of the 13
files, a group named in another case at its top level and in its opening job, a call of this
repository's and another's, `actions: write` and `issues: write` granted in a job, a secret named;
a new `workflow_run`, `workflow_call`, `repository_dispatch` or `workflow_dispatch` in each file
that lacks it (at least 30); the top-level grant removed from `docs.yml`, which makes each of its
jobs take the default. An upper-cased leading letter of a file's own group is the same group to the
platform and passes every set.

### The differential, extended

`run.sh` under `/Volumes/Lanes/out/bsv-rs/fix-1034-deny-shape-fold5/differential/` (the fourth
fold's scripts, reused): the fourth fold's 195 plants in every style the emitter offers, plus
`set_plants.rb`'s 297 for the sets, each in every style: for every file a new group, its own in
upper case, another's in another case, its expressions in upper case, `cancel-in-progress`
flipped, the short form, a second declaration in its opening job, the declaration moved there; for
every call another repository's, the file name in another case, `secrets: inherit` added; a call
of each kind in a new job of every file; each missing trigger kind added, each event's key in
another case; a grant added, `write-all`, `read` as `Read`, the top grant moved into a job, a job
grant added; a secret and the token named in upper case. A copy is seen when the parser reads the
plant (the fourth fold's criterion) or when the sets computed from the parser's own pairs differ
from the pins.

| | copies | seen | refused | difference |
|---|---:|---:|---:|---:|
| all | 39,475 | 26,779 | 26,779 | 0 |

Of the 26,779 (the judge asks the style, then the two whole pins, then the sets): 25,585 refused
by the style, 497 by the two whole pins, 697 by the sets; 21,679 of them are a change of a set by
the parser's own pairs (16,599 of the sets' plants, 5,080 of the earlier plants and equivalents).
Of the 12,696 copies
not seen, 31 pass every machine: 28 are a file's own group in upper case (the same group to the
platform), 3 the plant `---` respelled as an empty document, as in the fourth fold. Reader and
parser: 1,257 copies pass the style and parse, and the reader's pairs equal the parser's on all
1,257. The run took 4 minutes 7 seconds (59 s to respell, 182 s to judge; the copies' file,
815 MB, removed after it).

### Plants of my own, two per structure

- The path reader: a call written at indentation 6 (the re-read's), which a reader by column
  width would miss, is read by structure as `jobs/other/uses` (`the_reader_gives_every_key_path_and_its_value_1034`);
  a group quoted with ` #` inside it and a comment after it, `concurrency: 'Advisories #1' # a
  comment`, is read as `Advisories #1` (the comment cut after the closing quote, not at the earliest
  ` #`), in the same test.
- The pinned sets: `permissions: write-all` on a job, which names neither `actions` nor
  `issues`, is a row of `PERMISSIONS` and a holder (`p-all`, the differential). And one that
  slipped the five sets as they were built at the outset: a step running `gh run cancel` added to a job that already
  holds `actions: write` (`nightly.yml`'s `ci-full-beta`) changes no grant, no group, no call and
  no expression; so the sixth set, `HOLDERS`, pins each such job whole by a digest
  (`a_step_added_to_a_job_holding_a_grant_or_a_secret_is_refused_by_holders_1034`, RED by
  `HOLDERS` alone).

### What the records say, and the test behind each sentence

- "a concurrency group in another case, in any file, at the top level or a job's, fails by
  `GROUPS`": `each_kind_of_change_is_refused_by_its_pin_in_any_file_and_at_any_level_1034`.
- "a reusable workflow called at any indentation is read and pinned by `CALLS`":
  `the_re_reads_two_plants_are_refused_by_their_pins_1034`, `the_reader_gives_every_key_path_and_its_value_1034`.
- "the reader's pairs equal a real parser's on the 13 files and on every respelled copy the style
  lets through": the differential (1,270 and 1,257), no test of the tree (it needs Ruby).
- "no two files' groups can name one group": `no_two_files_groups_can_meet_whatever_their_expressions_give_1034`.
- "no job takes the repository's default token setting": `every_set_equals_its_pin_on_the_tree_1034`
  (`PERMISSIONS` holds no `the repository's default` row), and its removal RED in
  `each_kind_of_change_is_refused_by_its_pin_in_any_file_and_at_any_level_1034`.
- "a step added to a job holding a grant or a secret fails by `HOLDERS`":
  `a_step_added_to_a_job_holding_a_grant_or_a_secret_is_refused_by_holders_1034`.

### Stated bounds, as of the fifth fold

In one list, what no test in the tree holds: a reusable workflow of another repository, whose
file is not here (none is called; a call of one is a row of `CALLS`); the repository's default
token setting (no job takes it today, by `PERMISSIONS`); a run cancelled, re-run or a workflow
disabled by hand, in the settings, or by a token from outside the repository; what a secret's
token may do (each job holding a row of `SECRETS` is pinned whole by `HOLDERS`, the rows chosen by hand since the sixth fold); a composite action under
`.github/actions/` (none exists); a change inside an action the steps call (each pinned by its
sha); the toolchain and the runner image moving; a YAML spelling GitHub's parser reads and
libyaml does not (the differential's parser is libyaml 0.2.5). The pins catch deliberate edits
too: a new job holding a grant or a secret, a changed line of a holder, a new trigger input each
moves a set in the same commit.

## The sixth fold: the set of every expression is pinned

The re-read of the fifth fold (FIX 0.85) found everything the fold claimed held, save the two
sets about secrets and the token: `TOKENS` and the secret half of `HOLDERS` decided what an
expression names by matching three spellings (`secrets.`, `secrets[`, `github.token`), so a job
`leak:` appended to `docs.yml` with `env: ALL: ${{ toJSON(secrets) }}`, or with
`${{ github['token'] }}`, passed every test. The captain's ruling: the same mistake a fifth time,
one level in, a reader of text guessing at meaning; it ends by the structure the keys took.
Nothing about an expression's meaning is guessed: the complete set of expressions is pinned, a
job that adds or changes any expression anywhere fails by the pin's name, whatever the expression
says, and a deliberate change edits the pin in the same commit, where it is seen.

### Where an expression can stand

Read on 2026-11-18. The pages: (X) "Evaluate expressions in workflows and actions",
`docs.github.com/en/actions/reference/workflows-and-actions/expressions`; (K) "Contexts
reference", `.../reference/workflows-and-actions/contexts`; (W) "Workflow syntax for GitHub
Actions", `.../reference/workflows-and-actions/workflow-syntax`, read as its source
`github/docs` `content/actions/reference/workflows-and-actions/workflow-syntax.md` with the
include it names for a step's conditional, `data/reusables/actions/expression-syntax-if.md`
(the rendered page was cut before that section by the fetch).

| # | Where | What the documents say | Read by `key_paths` today | Here |
|---|---|---|---|---|
| 1 | `${{ ... }}` inside a scalar value on its key's line | (X) "You don't need to enclose strings in `${{` and `}}`." (an expression is the text inside them); (K) "As part of an expression, you can access context information using one of two syntaxes." | yes | pinned by this fold: `EXPRESSIONS` |
| 2 | `${{ ... }}` in an item of a flow sequence (a matrix list) | as 1 | yes (`<path>/[i]`) | pinned by this fold |
| 3 | `${{ ... }}` in a block scalar's body, literal or folded (`run`, `script` and the five other keys the style allows a block) | as 1; a `#` line inside a `run` body is the body's text | yes (the body as the parser reads it, a folded one joined) | pinned by this fold |
| 4 | `jobs.<job_id>.if` without delimiters | (W, the include) "When you use expressions in an `if` conditional, you can, optionally, omit the `${{ }}` expression syntax because GitHub Actions automatically evaluates the `if` conditional as an expression." | yes (the value) | pinned by this fold: the whole value |
| 5 | `jobs.<job_id>.steps[*].if` without delimiters | (W) "You can use the `if` conditional to prevent a step from running unless a condition is met.", then the include of row 4; "Secrets cannot be directly referenced in `if:` conditionals." | yes | pinned by this fold: the whole value |
| 6 | an `if` written as a block scalar | as 4 (the style allows `if` a block) | yes | pinned by this fold: the whole value |
| 7 | any other key taking a bare expression | none of the three pages names one: `run-name` "can include expressions", (C, the fifth fold's page) "A concurrency group can be any string or expression.", and the examples of `continue-on-error`, `timeout-minutes` and `strategy.matrix` write `${{ }}` | no such key | a stated bound: a key the platform read as a bare expression and the documents do not name is not pinned unless it holds `${{` (a key named `if` anywhere is pinned whole) |
| 8 | a mapping key holding `${{` | (K) "The listed contexts are only available for the given workflow key, and may not be used anywhere else." (a key's value) | no: the style refuses `$` in a key's name | inside the style |
| 9 | a matrix value with no `${{`, read by `${{ matrix.x }}` | no sentence on any of the three pages says whether a value an expression reads is evaluated again | yes (a pair) | a stated bound: the reading expression is pinned; the value is data to it (`the_folds_own_plants_are_refused_or_stated_1034` asserts it passes) |
| 10 | a matrix given by an expression (`${{ fromJSON(needs.x.outputs.y) }}`) | (X) the `fromJSON` example of `strategy.matrix` | yes | the expression pinned by this fold; the value a step writes at run time a stated bound |
| 11 | an input's default read by `${{ inputs.x }}` | (W) `on.workflow_dispatch.inputs`, `on.workflow_call.inputs` | yes | already inside a pinned set: `TRIGGERS` (every pair under the two events) |
| 12 | an `env` value with no `${{`, read by `${{ env.X }}` | as 9 | yes | a stated bound, as 9 |
| 13 | a YAML comment holding `${{` | a comment is no value | skipped, as the parser skips it | nothing to pin (row 3 holds a `#` inside a body) |
| 14 | the expressions of the blocks pinned whole (`advisories.yml` from `on:`, `release.yml`'s `advisories` job, `sibling-run.yml`, `sibling-judge.yml`, the `sibling` job) | | yes | already inside a whole pin, and rows of `EXPRESSIONS` too |

14 rows: 7 pinned by this fold (1, 2, 3, 4, 5, 6, 13 as nothing to pin beside 3), 3 already inside
a pin (8 the style, 11 `TRIGGERS`, 14 the whole pins), 4 stated bounds (7, 9, 10's run-time
half, 12). The functions (X) lists: `contains`, `startsWith`, `endsWith`, `format`, `join`,
`toJSON`, `fromJSON`, `hashFiles`, `case`, and the status checks `success`, `always`,
`cancelled`, `failure`; the forms: (K) "Index syntax: `github['sha']`" and "Property dereference
syntax: `github.sha`", and (X) "You can use the `*` syntax to apply a filter and select matching
items in a collection."

### The set

`EXPRESSIONS` (`tests/arch_workflow_pinned_sets_1034.rs`) holds every expression of every
workflow as `(file, key path, text as written)`: the whole value of each key named `if`, and each
`${{ ... }}` of every other value, closed at the earliest `}}` outside a single-quoted string
(the expression language's one string form; an unclosed one runs to the value's end). 347 rows:
`advisories.yml` 4, `bench.yml` 26, `ci.yml` 128, `docs.yml` 4, `features.yml` 4,
`front-pages.yml` 2, `machete.yml` 2, `msrv.yml` 2, `nightly.yml` 107, `release.yml` 8,
`sibling-judge.yml` 37, `sibling-run.yml` 11, `sync-main-into-beta.yml` 12; 88 of them `if`
values. Psych's tree, walked the same way (`scripts/exprs.rb` under the lane's logs), gives the
same 347 rows.

What became of the two sets that guessed: `TOKENS` is removed, and with it `names_a_token`; its
claim (every expression naming a secret or the job's token is written down) is carried by
`EXPRESSIONS`, which holds every expression whatever it names. `HOLDERS` stays, its secret half
now a named subset chosen by hand: `SECRETS`, 7 rows of `EXPRESSIONS` (the six jobs that are
handed a repository secret), chosen because a reviewer, not a matcher, judges meaning. No code
reads an expression's text for its meaning: `the_hand_chosen_secrets_are_rows_of_the_pinned_expressions_1034`
holds `SECRETS` inside `EXPRESSIONS`, and the holders, the same 12 jobs, are the jobs holding a
grant or a row of `SECRETS`.

RED by `EXPRESSIONS`: the re-read's two (`the_re_reads_secret_and_token_spellings_are_refused_by_expressions_1034`);
1,152 generated additions, 16 forms (the 13 functions, the dot, index and filter forms) over 12
contexts at six sites (a job's `env`, a step's `with`, a literal block, a folded block split over
two lines, a job's conditional with delimiters, a step's conditional without), each passing the
style, and each of the tree's 347 expressions changed by one character
(`every_added_or_changed_expression_is_refused_by_expressions_1034`). Four planted faults in the
reader, each RED and reverted: the scanner blind to quotes (1 of 10), an `if` not pinned whole (5
of 10), a `run` body unread (3 of 10), a row dropped from `SECRETS` (3 of 10).

### The differential, extended again

The fifth fold's run (`run.sh`, its scripts copied to `/Volumes/Lanes/out/bsv-rs/fix-1034-deny-shape-fold6/differential/`)
plus `expr_plants.rb`'s 450: 192 generated expressions (each function applied to each context,
the dot, index and filter forms), each at one of seven sites in turn across the 13 files (the top
level, an existing job, a new job's conditional without delimiters, a step's conditional without
delimiters, a step's `with`, a literal block, a folded block split over two lines), the seven
sites in every file with `toJSON(secrets)`, and 167 changes (each single-line expression and
conditional of every file changed by one character), each respelled in every style libyaml
0.2.5's emitter offers. A copy is seen as a new or changed expression when `EXPRESSIONS` computed
from the parser's own pairs differs from the pin.

| | copies | seen as a new or changed expression | refused | difference |
|---|---:|---:|---:|---:|
| all | 93,522 | 44,363 | 44,363 | 0 |

Of all copies seen (a plant, or a change of a set by the parser's pairs): 65,058, refused 65,058.
Of the 44,363: 35,602 refused by `EXPRESSIONS` on the reader's own pairs, the rest by the style or
a whole pin first. Reader and parser: 2,239 copies pass the style and parse, and the reader's
pairs equal Psych's on all 2,239. Respell 71 s, judge 224 s; the copies' file removed after it.

### Plants of my own

- An expression split over a folded block (`run: >-` with `${{ secrets.` and `ANY }}` on two
  lines): read joined, `${{ secrets. ANY }}`, RED by `EXPRESSIONS`.
- A matrix value that is an expression (`'${{ secrets.ANY }}'` added to `features.yml`'s
  `consumer` list): RED; a matrix word with no `${{` (`secrets.ANY`) passes, the stated bound of
  rows 9 and 12.
- A conditional as a bare word (`if: true` on a job of `docs.yml`): RED.
  All three in `the_folds_own_plants_are_refused_or_stated_1034`.

### What the records say since the sixth fold, and the test behind each sentence

- "the set of expressions is pinned; a change of it is deliberate and seen":
  `every_set_equals_its_pin_on_the_tree_1034`, `every_added_or_changed_expression_is_refused_by_expressions_1034`.
- "a secret or the token named in any spelling in a new job fails": `the_re_reads_secret_and_token_spellings_are_refused_by_expressions_1034`.
- "each job handed a secret is pinned whole": `a_step_added_to_a_job_holding_a_grant_or_a_secret_is_refused_by_holders_1034`
  over the hand-chosen `SECRETS`, held in `EXPRESSIONS` by `the_hand_chosen_secrets_are_rows_of_the_pinned_expressions_1034`.
- "a conditional without delimiters is pinned whole": `the_folds_own_plants_are_refused_or_stated_1034`,
  and the bare sites of the generated additions.

### Stated bounds, as of the sixth fold

The fifth fold's list stands, its secret clause read as above, and gains: what a pinned
expression may reach at run time is judged by no test (a secret's own rights; the repository's
settings; an action's default use of the token, which a step holding no expression may still
use); a key the platform reads as a bare expression that the documents do not name (row 7); a
value an expression reads that holds no `${{` (rows 9 and 12), and a value a step writes at run
time (row 10); whether a newly added expression hands a job a secret is the reviewer's to judge
when the pin moves (`SECRETS` is chosen by hand).
