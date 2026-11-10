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
   move (the procedure in the job's `SIBLING_PIN` comment; seen on the review of
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

What the pin cannot hold: the arch test, the workflow and the judge all travel in the pull
request's own tree, so a pull request that edits the job edits the pin beside it, where a
reviewer sees it. Holding that against a pull request by a machine is the next stage of #97
(the judge read from beta and reported by its own App).

## column.json

| Key | What |
|---|---|
| `sibling` | the sibling commit the column was read at (the job's `SIBLING_PIN`, `ci.yml`) |
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
(`crypto-00079`: #657). Moving the pin is a commit of its own (Q97.6): the job's
`SIBLING_PIN` and the re-recorded column together.

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
