# tests/sibling: the node's oracle, this crate's recorded column (#97, S1)

The sibling (`bsv-script-lean`, the bitcoin-sv node's consensus rules as a Lean
definition that runs) judges this crate's script verdicts with its own harness,
`harness/run --impl bsv-rs --spec recorded`. `.github/scripts/sibling_harness.py`
runs that harness against THIS tree (its one `bsv-rs` dependency line rewritten
to a path in a scratch copy, never in the sibling's tree) and judges the run in
two parts, the captain's ruling on Q97.5 under the owner's decision of 2026-11-10:

1. **VERDICTS, the node's.** Every applicable entry's verdict equals the
   sibling's specification column. An unexplained divergence or a message
   outside the sibling's code table fails, named from the corpus's log
   (`UNEXPLAINED <column> <id> ...`). A divergence a row of the sibling's own
   rules table explains (`harness/rules/bsv-rs.json`) fails too, named by its
   row: the owner's ruling of 2026-11-10 is zero divergences from the node, so
   an explained row is refused, never recorded, and a column whose `rules` is
   not empty (or whose `aborts_as_witnesses` is not 0) is refused when it is
   loaded, exit 2 (at the pin `rules` is empty and no entry aborts in every
   corpus). No waiver exists for this part, and the `VERDICTS:` headline counts
   an explained row among its divergences (#853's second fold: it printed `0
   divergences` above a RED line when only rules rows fired). The per-corpus
   counts (`entries`, `agree_mempool`, `agree_block`, `undecided`,
   `aborts_as_witnesses`) are compared with the column too. 73 entries are
   `undecided` at the pin (eras 42, tx 26, gen 5): a pre-Genesis spend or coin,
   which the crate's post-Genesis rule set has no word for
   (`ProtocolEra::at_height` is `None` below Genesis, `ScriptFlags::check`), so
   `run_diff` judges no verdict of theirs against the node; each is held by its
   words in REASONS (`undecided` and the not-applicable reason, under all three
   words), their count by compare, and each entry's `undecided` by `--record` at
   the pin; a pin move may change them (the next stage's guard). The sibling's own `bsv-rs@0.7.0` reason texts (`run_diff`'s
   `recorded_disagree`) are reported and never judged.
2. **REASONS, this crate's words.** `bsvrs_words` (`.github/scripts/sibling_words.rs`,
   dropped into the scratch copy beside `run_diff` and built on the harness's
   own adapter) writes, per entry, this crate's verdict and reason under the
   three words the harness runs: `rec` (the corpus manifest's recorded
   configuration), `spec` (the entry's own word) and `mempool` (the standard
   word). Each is compared with `column.json`'s `words`; a differing entry is
   named with both texts. A pull request that changes a reason on purpose
   re-records the column in the same commit, where a reviewer sees the line
   move; one that changes a reason by accident fails. A reword inside the code
   table that moves no verdict is recorded like any other, the out-of-scope
   prefix `Invalid verification flags: GENESIS is not set` included (the fold's
   re-read: `src/script/spend/mod.rs:511`'s truthy refusal so worded, 4,338 entries, RED on
   REASONS, then written by `--record`): a re-recorded column is a reviewed change of
   words, and the file-class rule of the next stage will hold it beside a crate change in
   the same diff; a reword that moves a verdict is refused by `--record` (an explained row,
   or at the pin the entry's verdict itself). Two changes cannot be
   carried by a pull request here, as the remedy is in the sibling: a new reason
   whose text no prefix of the sibling's code table (`harness/src/bsvrs_codes.rs`,
   `code_of`) matches is a message outside the table, RED on VERDICTS, and
   `--record` refuses it; and a change to a public item the harness's adapter
   builds against (`SpendParams` is built as a struct literal, `harness/src/engine.rs`)
   stops the harness build, exit 2. Each waits on the sibling's change and a pin
   move (a pull request of `tests/sibling/PIN` and the re-recorded column; seen on the review of
   PR #853: `flow.rs:168`'s OP_VERIFY text changed, 26 entries outside the table).

Every column the harness runs is under a node word (`set_flags`); none runs
`Spend` without one. The default mode (the reference's parity mode,
`Transaction::verify`'s) is not judged by this job: a change only it reaches
passes here (the review's witness: the default mode's shift-count bound at
`src/script/spend/splice.rs:265`, `>` to `>=`, GREEN on both parts).

## When it runs: always

The job (`ci.yml`'s `sibling`) runs on a pull request into beta, a push to beta, every
dispatch and a tag's call, and on every one of them it builds the harness and judges: there
is no reach filter (#853's fold, the captain's ruling of 2026-11-10). A list of paths decided
whether the PR's first head judged anything, and the reads found it missed `src/lib.rs`,
`build.rs` and a file renamed out of a listed path, and that no list can see a dependency's
release (no `Cargo.lock` is tracked, so each run resolves afresh). The measured cost: about
1m7s for the job on GitHub, its step 46 s cold with no cache. `tests/arch_ci_pr_runs_the_required_set.rs`
(`the_sibling_job_judges_on_every_event_it_runs_on_with_no_reach_filter_97`) refuses a
condition on any of the job's steps, a `needs:`, a job condition reading more than the event,
a path filter on ci.yml's triggers and a `sibling` step without `sibling_harness.py run`.
Since #853's third fold it holds the whole job and what the job inherits: the `sibling` job's
text, from its key line to its last line (`ci.yml:874-948` at the fold), equals the test
file's `SIBLING_JOB` byte for byte, and the workflow's `permissions:`, `concurrency:` and
`env:` blocks equal `SIBLING_INHERITS`, ci.yml's workflow-level keys `WORKFLOW_KEYS` alone (a
`defaults:` refused wherever it sits), so a change to the job or to what it inherits is a change
to the test in the same diff; a key after a comment is still read inside its block, and the
context `sibling` is reported by this job alone (a twin job in ci.yml or in another workflow
refused). A failure names ci.yml's line, the pinned line and the line found. The second fold
pinned the judging step alone, which a step inserted before it (one rewriting `column.json`
or the judge script, or writing `BASH_ENV` into `$GITHUB_ENV`), a job or workflow `env:`
key, a `container:`, another checkout action or `ref:` passed; each is refused now, and so are
the second fold's plants (`continue-on-error` on the step or the job, `|| true`, an `exit 0` or
an `echo` before the harness, `exit "$rc"` changed to `exit 0`, `--corpus seed`, `shell: sh`,
a job `defaults:`), the named rules above kept beside the pin to say why a change matters
(`the_sibling_job_and_what_it_inherits_are_pinned_whole_97`,
`the_sibling_step_is_pinned_and_no_failure_of_it_is_absorbed_97`). `shell: bash` is
GitHub's `bash --noprofile --norc -eo pipefail {0}`: the block stops at its first failing
command, and the harness's status is taken from `PIPESTATUS[0]` between `set +e` and `set -e`
and returned by `exit "$rc"`.

The pin lives in `tests/sibling/PIN` since #97's judge lane: one line of 40 lower-case hex
digits and a newline, read by the job's `pin` step (anything else refused) and handed to the
sibling's checkout and the judging step; `tests/arch_ci_sibling_judge_97.rs` holds the file and
its equality with `column.json`'s `sibling`. The pin moves by a pull request of that file and the
re-recorded column alone, never by an edit of `ci.yml`.

What the pin cannot hold, and what holds it now: the arch test, the workflow and the judge all
travel in the pull request's own tree, so a pull request that edits the job edits the pin beside
it. The two stages of the judge below hold that against a pull request by a machine (#97's wiring
lane): stage R (`.github/workflows/sibling-run.yml`, job `raw`) runs on every pull request into
beta with no secret and uploads the raw output; stage J (`.github/workflows/sibling-judge.yml`,
the trampoline, on main) judges it with beta's scripts, beta's pin rules and beta's column rules,
never the head's, and posts the App's check `sibling-judge`. A pull request that edits the
judging files is class J and judged by beta's copy of them; one that moves the pin is class P;
neither can change the rules its own verdict is read by. What remains is the manual's stated
limit (below, "What the judge does not hold"): the raw output is written by the head's own code
on the runner. `sibling-judge` is required by no protection until the owner's PATCH, after the
witnesses and the soak (`RELEASING.md` step 25), so until then the sentence above stays true of
what a merge needs.

## column.json

| Key | What |
|---|---|
| `sibling` | the sibling commit the column was read at (`tests/sibling/PIN`, read by `ci.yml`'s `sibling`) |
| `rules_pin` | `harness/rules/bsv-rs.json`'s `pin` at that commit |
| `withheld` | entries the public edition withholds (`"tx": "WITHHELD: ..."`), dropped from the staged copy per corpus: `gen` 150 at `1c051eae` |
| `corpora` | per corpus: the counts above, `unknown_messages`, the explained `rules` rows and the staged corpus file's sha256 |
| `notes` | an entry's ruled change, printed beside it when it differs; kept by `--record` while the entry is held |
| `words` | per corpus, per entry: one `[verdict, reason]` when the three words agree, else `{"rec", "spec", "mempool"}`; one line per entry |

Another `sibling`, `rules_pin`, `withheld` or corpus sha256 is exit 2: the
wrong pin, never a verdict. So is a corpus of the run that the column's
`corpora` or `words` does not carry (nothing would judge it), a corpus the
column carries that the run does not (a run judges the whole column; #853's
second fold, where a run over a subset exited 0), and a corpus of the run's
record (`sibling.json`) its manifest lacks, or the other way (its file and counts
would go unread). An entry the column holds and the run lacks is RED, named.

## Re-recording (one command)

From a GREEN-on-verdicts run of this tree, with the sibling checked out at the pin:

```sh
python3 -B .github/scripts/sibling_harness.py run --tree . --sibling <bsv-script-lean checkout> \
  --rev <pin> --corpus all --scratch <empty dir> --out <empty dir> --column tests/sibling/column.json \
  ; python3 -B .github/scripts/sibling_harness.py compare --manifest <out>/bsv-rs/manifest.json \
  --column tests/sibling/column.json --record
```

`--record` refuses a run with an unexplained divergence, a message outside the
sibling's code table, an explained rules row or an abort witness; and at the
column's own pin (`sibling` and `rules_pin` unchanged) it refuses a run whose
counts, corpus files, corpora or withheld counts differ from the column it
replaces, or any entry whose verdict under any of the three words (`undecided`
included) differs from the column's, entry by entry (#853's second fold: two
offsetting flips, one entry decided to undecided and another the other way, or
two verdicts swapped, kept every total and were written), naming at most 20
entries and then a count; so at a fixed pin it moves an error's words and
nothing else. The agreement class is not held per entry: at the pin the node's
verdicts are the corpus file's, whose sha256 is held, so it moves only with a
verdict. It writes the column's bytes (`column_text`: sorted keys,
one line per entry), never by hand. A ruled reason change adds its `notes` line
(`crypto-00079`: #657). Moving the pin is a commit of its own (Q97.6): `tests/sibling/PIN`
and the re-recorded column together, nothing else (the judge's class P).

## Exit codes

0 both parts GREEN; 1 a verdict divergence, an explained row, a count moved, or a
word that differs from the column (or an entry absent from either side); 2 a
setup stop (the harness did not build or was killed by a signal, another pin, a
corpus the column does not carry or the run does not, a run's record and
manifest naming other corpora, a `--record` at the pin that would move an
entry's verdict, a column carrying an explained row, an empty
or unreadable report, an error of the script itself, which prints a `SETUP STOP`
line the step summary carries). Measured on this host
(`docs/lanes/fix-97-s1.md`): about 18.5 s cold, 11 s with the crate rebuilt over
cached dependencies, 3 s warm, all nine corpora (13,765 entries).

## The judge (#97: built on beta by the judge lane, wired by `sibling-run.yml` and `sibling-judge.yml`)

The two-stage judge (decided 2026-11-10; the three design reads of 2026-11-12; the lane record
`docs/lanes/fix-97a.md`). Stage R, a workflow on the pull request's head with no secret, checks
the head out to `head/` and beta to `judge/` and runs beta's script on the head's tree (the head's
own `.github/scripts/` is never executed, so a J diff cannot change the script that writes its own
artifact; the rule read's R2 of lane 1, pinned by `test_sibling_judge.py`'s `StageRScript`):

```sh
python3 -I -B judge/.github/scripts/sibling_harness.py raw --tree head --sibling sibling \
  --corpus all --scratch <empty dir> --out <empty dir> --head-sha <head> [--pull-request <n>]
```

and uploads the files `python3 -I -B judge/.github/scripts/sibling_judge.py members` lists as the
artifact `sibling-raw` (`sibling_judge.py pack --out <out> --zip <file>` zips them as the upload
holds them). `raw` judges nothing and reads no column; it writes `stamp.json` beside the run's
files and exits 0 whenever the harness ran to a verdict. Stage J, on the default branch, checks
beta out and runs `sibling_judge.py judge` there, holding no key, then `sibling_judge.py report`,
the one job holding the App's token (`bsv-rs-sibling-judge`, ID 5700082, from the environment
`sibling-judge`), which creates the check run `sibling-judge` once, already completed. The
script names no App id and no secret: the id is an option, the token the environment's.

`judge`'s rules, in this order (the shape of the change before the state of the run, so a bad
pin reads `REFUSED` and never `NOT JUDGED`):

1. **The run and the pull request.** The head is the run's `head_sha` as GitHub answers
   `actions/runs/<id>`; the run's `path` is `.github/workflows/sibling-run.yml` (never its
   name), its `head_repository.id` this repository's, its event `pull_request` or
   `workflow_dispatch`, and `commits/<head>/pulls`, asked at judge time, holds an open pull
   request with that head, both repositories this one, base `beta`. Otherwise no check, a line
   in the log (`post` `no`). A run a newer `sibling-run` run or a newer attempt supersedes earns
   no check either. No branch name enters a URL.
2. **The two lines.** Every beta fact is read at one sha, `git rev-parse HEAD` of the judge's
   checkout; main is `github.workflow_sha`. The file the run executes
   (`<workflow_sha>:.github/workflows/sibling-judge.yml`) must be beta's, else `NOT JUDGED`
   naming the line that is behind.
3. **The head.** Never checked out: its `tests/sibling/PIN` and `tests/sibling/column.json`
   are blobs read by `git cat-file` after a fetch by sha, mode 100644 each. The head must hold
   beta's sha (`git merge-base --is-ancestor`), else `REFUSED: behind beta by N commits`.
4. **The class**, from `git diff --raw -z --no-renames --no-abbrev <beta> <head>` (the names and
   modes, a rename its old name deleted; no API list, whose compare stops at 300 files and whose
   pull request files at 3,000); a mode other than 100644 at a J, P or W path refused. The table,
   the earliest match deciding:

   | Class | Paths |
   |---|---|
   | P | `tests/sibling/PIN` |
   | W | `tests/sibling/column.json` |
   | N | `CHANGELOG.md`, `docs/**`, every `CLAUDE.md` |
   | J | `.github/workflows/sibling-run.yml`, `.github/workflows/sibling-judge.yml`, every path under `.github/scripts/` whose file name or a directory name carries `sibling_`, every other path under `tests/sibling/`, `tests/arch_ci_sibling_judge_97.rs` |
   | C | every other path, `.github/workflows/ci.yml`, `.github/workflows/sync-main-into-beta.yml` and `tests/arch_ci_pr_runs_the_required_set.rs` among them |

   At most one of J, P, C; N rides with any; W rides with C, with P or alone, never beside J (so
   in a J diff the column is beta's). No class makes a check green by itself: every class is
   judged from its artifact. A J diff's title reads `JUDGE CHANGE: <paths>`, in place of `GREEN`
   or after a failure's opening word. N cannot move a verdict:
   `tests/arch_ci_sibling_judge_97.rs` refuses an `include_str!`, `include_bytes!` or
   `include!` of such a file under `src/` or in `build.rs`.
5. **The pin.** The head's PIN blob is `^[0-9a-f]{40}\n$`, beta's unless the class is P, and
   `repos/Calhooon/bsv-script-lean/compare/<pin>...main` answers `behind_by` 0 (a commit only a
   fork of the sibling carries, which GitHub serves by sha through the parent, is refused).
6. **The column's rules** (2026-11-10): no explained row and no abort witness; recorded at the
   head's pin (its `sibling`, `rules_pin`, `withheld` and every corpus sha256 the judge's own
   staging of the sibling at the pin, fetched by sha, nothing of it executed); outside P it moves
   words alone against beta's (`held_at_the_pin`, `verdicts_moved`); in P no corpus and no judged
   entry is dropped, `withheld` does not grow, and an entry whose corpus line the pin move left
   unchanged keeps beta's words.
7. **The run's state.** The artifact is read only from a run whose attempt ended `success`;
   any other conclusion is `NOT JUDGED` naming it and the failed step. Exactly one unexpired
   `sibling-raw` of the run, its head and this repository, created at or after the judged
   attempt's `run_started_at` (stage R uploads with `overwrite: true`, so a re-run replaces the
   earlier attempt's artifact, and one GitHub still lists from before the attempt is not counted:
   a re-run is judged, never `NOT JUDGED`, `test_sibling_judge.py`'s `Rerun`); none or two is
   `NOT JUDGED`, and a
   dispatch whose artifact is gone posts `unless-standing` (nothing over a standing check). The
   zip is taken by `gh api .../artifacts/<id>/zip` (it follows the 302 to storage) and read in
   memory by the allowlist: no extraction, no `download-artifact`, nothing written under the
   workspace; an unlisted, repeated or oversized member (64 MiB the artifact, 16 MiB a member,
   on the declared sizes), a `..` or a leading `/`, a symlink entry or an unknown `schema` is
   refused. The stamp and the run's record are compared with what the judge read and never used.
8. **The verdict**, `judge_run` over the artifact's files, the head's column and the judge's own
   corpus facts. Then `post`, `conclusion` (`success` or `failure` alone: `neutral` and
   `skipped` would satisfy a required check), `title` and `text` (base64) go to the outputs.

A failed check's title opens with one of three words: `RED` (a divergence: the change's),
`REFUSED` (its shape: the classes, the pin, the column's rules, a head behind beta) or
`NOT JUDGED` (stage R, the artifact, the trampoline, GitHub: re-drive). Every string from the
artifact or the head goes into the text inside one fenced block (backticks and control bytes
replaced, 500 bytes a line, 60,000 characters in all, the lines cut counted), save a J diff's
path names, which the title carries after `JUDGE CHANGE: ` (the same bytes replaced, the title
cut at 240 bytes); the script prints
none of it to its log. Every failed check ends with the command that re-judges it (the App has
no webhook: its check's Re-run button does nothing). `judge` and `report` exit 0 whenever a
verdict was reached and posted or nothing was posted on purpose, non-zero only when `report`
could not report: a `workflow_run`'s own jobs sit on main's tip, and a RED in a pull request must
never paint the stable line red.

**A change that needs both sides at once.** A J diff is judged like any other, from its
artifact, with beta's script in stage R (run on the head's tree) and beta's judge in stage J. So a change of an interface the two stages share lands in two pull
requests, the reader made tolerant and then the writer: the `raw` command's options with the
workflow that calls it; `stamp.json`'s fields with the judge's stamp check; the artifact's
members with `members`; `sibling_words.rs` with a public item the harness's adapter builds
against. One that cannot be split is the lift RELEASING describes (the owner's alone).

**The dry run and the sweep.**

```sh
python3 -I -B .github/scripts/sibling_judge.py judge --dry-run --artifact <zip or raw tree> \
  --head <sha> [--beta <sha>] --judge <checkout holding both> --sibling <bsv-script-lean repo> \
  [--pull-request <n>] [--offline]
python3 -I -B .github/scripts/sibling_judge.py sweep --app-id 5700082
```

The dry run calls no GitHub write (and with `--offline` no read: the pin's place on the
sibling's `main` is then unmade) and prints the check it would post; it says which rules it could
not make (the run's identity, the superseded test, the artifact's record, the trampoline's
comparison). The sweep reads and never writes: for every open pull request into beta its head,
its newest completed stage R run and whether the App's check stands (a completed check whose
app id is the configured one: a check with no app id never stands, the rule read's R3), and the
act for each gap as a command, the branch name quoted by `shlex.quote` there and in every re-push
act a check carries (no run, a run and no check, a conflict with beta, a fork's head).

## Where no check is posted, and the re-drives

Silence is named, not excluded (`RELEASING.md` step 25 carries the same list). No `sibling-judge`
check is ever posted for: a pull request in conflict with beta (GitHub starts no `pull_request`
run); a skip instruction in the head's commit message; a head pushed with the `GITHUB_TOKEN` (the
sync's branch until the sync's own dispatch of `sibling-run.yml`); a `sibling-run.yml` that does
not parse or changes its `name:` (the trampoline's `workflow_run` names `sibling-run`); a base
changed to beta after the pull request opened; a token step that fails; an environment that
refuses the `report` job; an event GitHub drops. The two re-drives:

```sh
gh workflow run sibling-run.yml --repo Calhooon/bsv-rs --ref <branch>        # a new stage R on the head
gh workflow run sibling-judge.yml --repo Calhooon/bsv-rs --ref main -f run_id=<run>   # the run judged again
```

and the sweep (`sibling_judge.py sweep --app-id 5700082`) names every open pull request's gap
with its act. Both workflows carry the head's sha in their `run-name:`, a re-judge dispatch of `sibling-judge.yml` the stage R run's id. A re-run of stage R is
judged from its own attempt's artifact (`overwrite: true` on the upload, the judge's attempt
filter), never `NOT JUDGED`.

## What the judge does not hold

The judge holds the judging files, the pin and the column against a pull request; it does not
hold the raw output against the head's own code, since stage R runs the head's `build.rs`, its
dependencies and the crate itself on the runner that writes that output. A head that lies in its
raw output (a `build.rs` that rewrites the words, a crate that prints the column's answers) is
held by the reads of the change, no machine.

A RED on beta's own push run of `sibling` (a dependency's release: no `Cargo.lock` is tracked, so
each run resolves afresh) turns every pull request RED with no change of its own at fault, and
holds them all until the repairing pull request lands.

The tests: `.github/scripts/test_sibling_judge.py` (hermetic: a fake of the one GitHub class
counting every write, a sibling, an upstream and beta's clone built under a temporary directory;
`fixtures/sibling_judge/` holds the two run records of 2026-11-12 as GitHub answered them, less the
fields the judge never reads, the `path` alone replaced; no real fork is used, the identity
table's foreign `head_repository.id` is that witness), run by `checks`' `judge-tests` with
`test_sibling_harness.py`; and `tests/arch_ci_sibling_judge_97.rs`, which also pins both workflows
whole, byte for byte, beside the named rules of each (`stage_r_holds_its_named_rules_97`,
`stage_j_holds_its_named_rules_97`, `the_key_the_environment_and_workflow_run_belong_to_the_trampoline_alone_97`).
