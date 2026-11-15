# Lane fix-849-security-page: the security page and the release ritual say where an advisory is published (2026-11-14)

Started from `origin/beta` at `5ad961d7bfeb883bca397e29e31b735e1b1b9ba6`, and rebased at the end,
onto `228d4f34c6b658d451516cafdd6f46951822534e` and then onto
`1acd0854cf1c5cb7704495db8a36dc97edfab6cb`: three commits landed on `beta` during the lane (two of
documents and comments, one of the benchmark baseline), and each time `CHANGELOG.md` took both
sides' entries under `[Unreleased]`, this lane's on top; no other file of this lane met theirs. Nothing pushed, nothing
written to GitHub or to any other repository. Reads alone, by `gh` and two public HTTP APIs, each
listed below with its answer. Documents and the two tests that hold them: no file under `src/`,
no workflow, no script.

## The issue's comments

Six comments on Calhooon/bsv-rs#849, 2026-11-10 to 2026-11-13: the publication of 0.8.5, 0.8.6,
0.8.7, 0.8.8 and 0.8.9 with their advisories, and one line from the builder of #848's fix (a
stable port of #848 is the tracker's to decide; untouched here). No comment records a decision
that binds this lane, and none waits on something this lane needs. Each publication comment says
"a CVE requested" and names a RustSec pull request: what those sentences say against today's
record is under "The CVE" below.

## The premise, checked on this tip

| Cited by the brief | On `5ad961d7` |
|---|---|
| `SECURITY.md:41`: published "on GitHub (with a CVE requested) and in the RustSec advisory database" | holds |
| `SECURITY.md:46`: "Each is also filed with the RustSec advisory database" | holds; `:42` beside it said the advisory reaches users "through `cargo audit` and `cargo deny`" |
| `RELEASING.md` step 14 at `:34` | the step is line `:32`; its last two sentences owed the RustSec database a second pull request for a patched prerelease |
| `RELEASING.md` step 23 (f) at `:57` | the step is line `:55`: "a CVE requested and a RustSec entry filed from it", and point (iv), the lessons of filing RustSec files |
| the class list at `:40`: "a security advisory (a RustSec entry against this crate or a dependency)" | holds at `:40`; read, and left (below) |
| no published advisory has a CVE | holds: six published, `cve_id` empty on each |
| the Security tab "is GitHub's advisory database (what Dependabot and `gh` read)" | does NOT hold as written: `gh api repos/Calhooon/bsv-rs/security-advisories` reads the repository's list, but the GitHub Advisory Database, the one Dependabot reads, lists none of the six (the read below). The page says what the read shows |

## The reads of 2026-11-14

1. This repository's published advisories:
   `gh api repos/Calhooon/bsv-rs/security-advisories --paginate --jq '.[] | select(.state=="published") | [.ghsa_id, (.cve_id // "-"), .severity, .published_at, ...] | @tsv'`.

   | Advisory | CVE id | Severity | Published | Stable range, patched | Prerelease range |
   |---|---|---|---|---|---|
   | GHSA-j8hr-pjhm-6h27 | none | high | 2026-11-10T20:53:11Z | `< 0.8.5`, 0.8.5 | `>= 0.9.0-beta.1, <= 0.9.0-beta.7`, no patched prerelease named |
   | GHSA-9c8r-76f3-m426 | none | medium | 2026-11-11T16:58:50Z | `< 0.8.6`, 0.8.6 | the same |
   | GHSA-84xq-3662-pvx5 | none | medium | 2026-11-11T16:58:51Z | `< 0.8.6`, 0.8.6 | the same |
   | GHSA-cwxv-4866-5gq2 | none | critical | 2026-11-12T00:53:25Z | `>= 0.2.0, <= 0.8.6`, 0.8.7 | the same |
   | GHSA-gg5p-wgff-v3hr | none | medium | 2026-11-12T23:32:52Z | `>= 0.2.0, < 0.8.8`, 0.8.8 | the same |
   | GHSA-mj2m-jxgv-r446 | none | high | 2026-11-13T03:08:25Z | `< 0.8.9`, 0.8.9 | the same |

   The same list answers an unauthenticated read
   (`https://api.github.com/repos/Calhooon/bsv-rs/security-advisories`): six, all published. That
   is the line the page gives a reader's script.

2. The public RustSec database, `rustsec/advisory-db` at `4ef2df8e806a65e2f1ecc14f56f51249062b23d6`
   (its `main` on 2026-11-13T12:33:03Z), folder `crates/bsv-rs/`: six files, each one's front
   matter read (`gh api repos/rustsec/advisory-db/contents/crates/bsv-rs/<file>?ref=4ef2df8e...`).

   | File | `aliases` | `patched` |
   |---|---|---|
   | RUSTSEC-2026-0497 | GHSA-84xq-3662-pvx5 | `>= 0.8.6, < 0.9.0-beta.1`; `> 0.9.0-beta.7` |
   | RUSTSEC-2026-0498 | GHSA-j8hr-pjhm-6h27 | `>= 0.8.5, < 0.9.0-beta.1`; `> 0.9.0-beta.7` |
   | RUSTSEC-2026-0499 | GHSA-9c8r-76f3-m426 | `>= 0.8.6, < 0.9.0-beta.1`; `> 0.9.0-beta.7` |
   | RUSTSEC-2026-0500 | GHSA-j8hr-pjhm-6h27 | `>= 0.8.5, < 0.9.0-beta.1`; `> 0.9.0-beta.7` |
   | RUSTSEC-2026-0501 | GHSA-cwxv-4866-5gq2 | `>= 0.8.7, < 0.9.0-beta.1`; `> 0.9.0-beta.7` |
   | RUSTSEC-2026-0529 | GHSA-mj2m-jxgv-r446 | `>= 0.8.9, < 0.9.0-beta.1`; `> 0.9.0-beta.7` |

   Five of the six advisories are listed, under six ids; no file's `aliases` names
   GHSA-gg5p-wgff-v3hr. Every file names every version after `0.9.0-beta.7` under `patched`, which
   is why `RELEASING.md` step 14 owes that database nothing when a patched prerelease publishes.

3. OSV (`POST https://api.osv.dev/v1/query`, package `bsv-rs`, ecosystem `crates.io`): six
   entries, the six RUSTSEC ids above with the same aliases, and no other.

4. The GitHub Advisory Database (`github.com/advisories`): `gh api advisories/<GHSA id>` answers
   404 for each of the six; `gh api 'advisories?ecosystem=rust&affects=bsv-rs&type=reviewed'` and
   the same with `type=unreviewed` answer empty lists. Control: the same query with
   `affects=openssl` answers reviewed advisories. So that database listed none of the six that
   day. GitHub's page on Dependabot alerts says "Only advisories reviewed by GitHub trigger
   alerts", which is the ground of the page's sentence that none of the six raised one that day.

5. crates.io (`https://crates.io/api/v1/crates/bsv-rs`): `max_stable_version` 0.8.9, the newest
   prerelease 0.9.0-beta.7, nothing yanked among the twelve newest versions.

6. The front pages' reconciler, read-only (`python3 -I -B .github/scripts/front_pages.py check`):
   three rules red that day, none of them this lane's: `notices` (58 Release pages inside the
   range of GHSA-gg5p-wgff-v3hr or GHSA-mj2m-jxgv-r446, or fixing one, do not name it; v0.8.8's
   page lacks its Fixes line), `readme` (the README crates.io shows for 0.8.9 names versions
   before its examples) and `about` (the repository's homepage field against the manifest's).
   Because of the `notices` answer the page does not say that every Release page names the
   advisories that touch its version; it tells the reader to watch the releases and read the
   Security tab.

7. Whether a watch with "Security alerts" notifies a watcher when a repository's advisory is
   published: GitHub's page on configuring notifications lists the option and does not say what
   it covers. Not verified, so the page does not name it; it names the Releases watch and the
   releases feed (`https://github.com/Calhooon/bsv-rs/releases.atom`, read: HTTP 200, an Atom
   feed).

## The CVE

GitHub's record shows no CVE id on any published advisory. The tracker's body and its five
publication comments, and `docs/design/843-identity-and-framing.md` (`:206`, `:261`), say a CVE
was requested for each. The repository advisory API shows an id once one is assigned and no
state of a request, so no read of this lane decides whether a request stands. The page says what
is read and what is done: no advisory of this crate has a CVE id (GitHub's record on 2026-11-14),
and a CVE is requested for an advisory only where the page names the advisory. The older
sentences stand as written in their dated records; if a request does stand for one of the six,
the page's sentence is the place to name it.

Changed by the fold of 2026-11-15 (the last section of this record): a CVE was requested for
each of the six, and the page now says so and claims no rule.

## What changed

- `SECURITY.md`: "What happens after a report", steps 3 and 4; "Published advisories", rewritten:
  the Security tab as the record and the one place; what `cargo audit`, `cargo deny` and
  Dependabot report; the closed table of the six advisories published through 2026-11-13; the
  CVE sentence; how to hear of an advisory. The two audit sentences `tests/front_page.rs` F10
  pins, and the README's F10 line, are untouched.
- `RELEASING.md`: step 14 (nothing owed to the RustSec database for a patched prerelease); step
  23 (f) (where the advisory is published; no file, no pull request, no CVE request unless the
  page names it), its point (i) (no `SECURITY.md` row written by a sitting) and its point (iv)
  (the decision in place of the filing's lessons, which remain in this file's history at
  `5ad961d7`).
- `docs/design/843-identity-and-framing.md`: section 9 gains item 9 (the change, dated) and item
  5 a pointer to it; section 8's open row for GHSA-j8hr-pjhm-6h27 says its RustSec half ended.
- `tests/front_page.rs`: one test and its helpers. `tests/arch_ci_lines.rs`: one test and its
  helper.
- `tests/CLAUDE.md` (the two rows, one summary line), `CHANGELOG.md` (the entry under
  `[Unreleased]`), this record.

The table is closed by design. The page removed a hand-kept table of advisories on 2026-11-11
(`3814053b`) because such a table goes stale. This one is a dated record of one read, of a set
that is complete (the advisories published before the decision took effect), so no sitting owes
it a row and nothing later can make it stale but a change in a public database, which the date
covers.

## What stands, and why

`git grep -n -i -w -E 'rustsec|cve' -- . ':!CHANGELOG.md' ':!docs/lanes'` on the tip, every hit
this lane did not write or mend:

| Where | Stands because |
|---|---|
| `RELEASING.md:40`, the direction rule's class "a security advisory (a RustSec entry against this crate or a dependency)" | it names an advisory this crate receives, the kind `cargo deny` reads from that database (0.8.3's RUSTSEC-2026-0387 was one). Left as the brief asks. One thing for the captain: an advisory of this crate published after 2026-11-13 is no RustSec entry, and reaches the class through step 23's "the security-advisory class above" alone. Changed by the fold of 2026-11-15 (the last section): the class names both kinds |
| `RELEASING.md:16`, `deny.toml:6`, `docs/ARCHITECTURE.md:165` | the `deny` gate reads the RustSec database for this crate's dependencies; unchanged and true |
| `Cargo.toml:39`, `HANDOFF.md` (five lines) | RUSTSEC-2026-0387, a dependency's advisory, and the record of 0.8.3 |
| `docs/design/843-identity-and-framing.md:155`, `:189`, `:194`, `:206`, `:207` | the owner's words of 2026-11-10, the plan "as written" and the record "as it happened", each dated; item 9 of section 9 says what changed |
| `src/block/CLAUDE.md` (three lines), `src/block/merkle.rs:35` | CVE-2012-2459, the merkle mutation, no advisory of this crate |

Outside that grep, by the brief: `CHANGELOG.md` (three lines before this entry: RUSTSEC-2026-0387 twice, CVE-2012-2459) and three older lane records under `docs/lanes/`, each saying what was done in its day.

## RED

Each on a scratch copy of `5ad961d7` (a `git archive` of the base with the one test file
overlaid, a target dir of its own, removed after).

- `tests/front_page.rs`,
  `the_security_page_says_where_advisories_are_published_and_that_none_is_filed_to_rustsec_849`:
  1 of 11 failing, sixteen refusals: the nine sentences absent, six stale claims at
  `SECURITY.md:41`, `:42` and `:46`, and no table. Log `red-front_page.log`.
- `tests/arch_ci_lines.rs`,
  `releasing_publishes_an_advisory_on_the_security_tab_and_files_none_with_rustsec_849`: 1 of 24
  failing, fourteen refusals: seven duties at `RELEASING.md:32` and `:55`, seven sentences
  absent. Log `red-arch_ci_lines.log`.

Green on the tip: 11 of 11 and 24 of 24, three runs, one with `--test-threads=1`.

Where each test lives, and why: the page's test sits in `tests/front_page.rs`, the test the
direction rule's fifth class names, so it travels to `main` with the front-page machine and reads
`SECURITY.md` alone (a `SECURITY.md` change already reaches that binary, so CI's plan does not
move). The ritual's test sits in `tests/arch_ci_lines.rs`, which already reads `RELEASING.md`
(#958), so a `RELEASING.md` change reaches no binary it did not reach before; it asks its
sentences only of a ritual that describes a security patch's sitting, so `main`'s older ritual
would be judged for the stale duties alone.

## The gate

Run on `5ad961d7` with the change, and every line of the table run again after the rebase onto
`228d4f34`. After the rebase onto `1acd0854`, whose commit holds no Rust source, the Rustfmt
lines, the tests of the table, the rows check and gitleaks were run again and the rest was not. On
macOS, one cargo at a time, `CARGO_BUILD_JOBS=2` (the host's swap sat above half: 3.6 of
5.1 GB), a target dir of the lane's own, removed at the end with the ratchet's and the scratch
copy's. Logs under `/Volumes/Lanes/out/bsv-rs/fix-849-security-page/`.

| Gate | Result |
|---|---|
| Rustfmt, the lint step's three lines, with 1.100.0 (CI's stable) and again with the host's 1.95.0 | clean |
| `cargo +1.100.0 clippy --all-features --locked --test front_page --test arch_ci_lines -- -D warnings` | clean |
| `cargo +1.100.0 check --all-targets --all-features --locked` | passes; four `cargo::unused_dependencies` manifest warnings of cargo 1.100.0 (`dhat` twice, `futures-timer`, `js-sys`), the base's |
| `cargo test --features "full,http" --test front_page --test arch_ci_lines --locked`, three runs, one single-threaded | 11 and 24 passed each run |
| `cargo test --features "full,http" --test 'arch_*' --locked` | 37 binaries, 196 passed, 0 failed, 1 ignored |
| `--test fixtures_replay`, `--test readme_examples` | 1 and 1 passed |
| `RUSTDOCFLAGS=-Dwarnings cargo +1.100.0 doc --no-deps --all-features --locked` | built |
| `tools/ratchet/run --check --against` the base | all 7 counters, oversized-file limits and mutation floors pass |
| `python3 .github/scripts/mutants_entries.py` (cargo-mutants 27.1.0) and its 13 unit tests | PASS: 28 entries |
| `python3 .github/scripts/rows_from_sources.py --check` and its 10 unit tests | 0 refusals |
| gitleaks 8.30.1, git mode, the lane's one commit | no leaks |

No workflow and no script of `.github/` changed, so `actionlint` and the scripts' own tests had
nothing new to read. The wasm32 build of rule 6 was not run: no file under `src/` changed.

## What the pick to `main` carries

`SECURITY.md` alone, under the direction rule's fifth class. `main`'s page differs from `beta`'s
above the changed lines (no "Audits" section, an older step 2), so the cherry-pick stops on
context at step 2: the resolution keeps `main`'s lines down to step 2 and takes this commit's
text from step 3 to the end of the file. Every other file of the commit stays `beta`'s: `main`
has no `tests/front_page.rs` (it arrives with the front-page machine's pick, and its new test is
green there once `main`'s `SECURITY.md` carries this text), no step 14 or 23 of this form in its
`RELEASING.md`, no `docs/design/843-identity-and-framing.md`, and its own `tests/arch_ci_lines.rs`
and `tests/CLAUDE.md`.

## Not verified

- The table's "Patched in" is each advisory's published record. No sentence of it was run again
  on the published crates by this lane.
- Whether a CVE request stands for any of the six ("The CVE" above).
- That none of the six raised a Dependabot alert on 2026-11-14 is read from the database's
  answer and GitHub's documented rule, not from a repository's alerts.
- What either public database lists after 2026-11-14.
- A Linux or Windows run of the two tests (the Windows cells check Markdown out with CRLF; the
  tests read whole lines and substrings inside one line).

## The fold of 2026-11-15

One commit on top of the lane's `55b164ce3f38ac859d3be4b1b54ccdf4ea33cce3` (lane
`fix-849-security-page-fold`, on the Studio). The rule read of pull request #1004 found two
sentences of the lane that the next release makes false. Both are folded here, each with its pin.
Nothing pushed, nothing written to GitHub; reads alone. No file under `src/`, no workflow, no
script.

### Item 1: the direction rule's class of a security advisory

`RELEASING.md:40` read `- a security advisory (a RustSec entry against this crate or a
dependency);`. No advisory of this crate published after 2026-11-13 is a RustSec entry (step 23
(f)(iv)), so by that letter the next security patch of this crate had no class that admitted it; the lane left
the sentence and said so ("What stands, and why"). It now names both kinds:

> - a security advisory: of this crate, one drafted on this repository's Security tab (step 23;
>   an advisory of this crate published after 2026-11-13 is no RustSec entry, step 23 (f)(iv));
>   against a dependency, an entry of the RustSec advisory database, which `cargo deny` reports
>   (step 2);

`main`'s own `RELEASING.md` carries the older sentence at its line 18 (`origin/main` at
`ca047fec`) and no step 23. It is not this pull request's to change: a pull request into `beta`
reaches `main` by a pick of the six classes, and the ritual's words are none of them. The pin
judges the older sentence only beside a security patch's sitting, so that ritual passes it as it
passed before. Whether `main`'s sentence moves before the cut is the captain's.

### Item 2: what is true of a CVE

The lane's page said "No advisory of this crate has a CVE id (GitHub's record on 2026-11-14). A
CVE is requested for an advisory only where this page names the advisory and says so, and it
names none", its step 3 said "and no CVE is requested", and `RELEASING.md` step 23 (f) and its
point (iv) said "no CVE is requested unless `SECURITY.md` names the advisory and says so". Two
things were wrong with that. A CVE was requested from GitHub for each of the six advisories at
its publication. And nobody decided that none is requested for a later advisory: the decision of
2026-11-13 that the lane cited is about the RustSec advisory database alone.

The reads of 2026-11-15:

1. This repository's published advisories, at 13:43:58Z
   (`gh api repos/Calhooon/bsv-rs/security-advisories --paginate --jq 'map(select(.state == "published")) | map({ghsa_id, cve_id, published_at})'`):
   six, `cve_id` null on each.

   | Advisory | `published_at` | `cve_id` |
   |---|---|---|
   | GHSA-j8hr-pjhm-6h27 | 2026-11-10T20:53:11Z | none |
   | GHSA-9c8r-76f3-m426 | 2026-11-11T16:58:50Z | none |
   | GHSA-84xq-3662-pvx5 | 2026-11-11T16:58:51Z | none |
   | GHSA-cwxv-4866-5gq2 | 2026-11-12T00:53:25Z | none |
   | GHSA-gg5p-wgff-v3hr | 2026-11-12T23:32:52Z | none |
   | GHSA-mj2m-jxgv-r446 | 2026-11-13T03:08:25Z | none |

2. The public record of each request, on Calhooon/bsv-rs#849 (`gh issue view 849 --comments`),
   each comment the record of one release and of the day of its advisory's publication:

   | Release | Advisory | The comment | Its words |
   |---|---|---|---|
   | 0.8.5 | GHSA-j8hr-pjhm-6h27 | 2026-11-10T21:05:16Z | "a CVE is requested" |
   | 0.8.6 | GHSA-9c8r-76f3-m426, GHSA-84xq-3662-pvx5 | 2026-11-11T17:02:34Z | "A CVE is requested for each" |
   | 0.8.7 | GHSA-cwxv-4866-5gq2 | 2026-11-12T00:56:04Z | "published 00:53 UTC with a CVE requested" |
   | 0.8.8 | GHSA-gg5p-wgff-v3hr | 2026-11-12T23:35:31Z | "published 23:32 UTC with a CVE requested" |
   | 0.8.9 | GHSA-mj2m-jxgv-r446 | 2026-11-13T03:10:05Z | "published 03:08 UTC with a CVE requested" |

   The issue's body says the same of 0.8.5's ("a CVE requested"), and
   `docs/design/843-identity-and-framing.md` section 6, written on 2026-11-10, "a CVE requested,
   none assigned when this was written". The five Release pages (`gh release view v0.8.5` to
   `v0.8.9`) name no CVE, and no other pull request or issue of the repository records a request
   (`gh search prs` and `gh search issues` for the word: #884's body, on the table the page
   dropped on 2026-11-11, and #843's plan).

3. What no public read shows: the state of a request. GitHub's API gives an id once one is
   assigned and nothing before, so "a CVE was requested from GitHub" rests on the five comments,
   on the plan they followed (a GitHub advisory "with a CVE requested", the design record's
   section 6 and section 9 item 5) and on the captain's brief for this fold; "at its publication"
   is the comments' own words for three of the six and their timing for the other three (each
   comment was written between 1 minute 40 seconds and 12 minutes 5 seconds after its
   advisory's `published_at`).

What each document says now:

- `SECURITY.md`, step 3: "No file is sent to the RustSec advisory database ("Published
  advisories", below; "CVE ids" there says what is true of a CVE id)." It no longer says "and no
  CVE is requested".
- `SECURITY.md`, a part `### CVE ids` in the place of the two sentences quoted above: a CVE was
  requested from GitHub for each of the six advisories of the table, at its publication, each
  named with its day (the days of the table in read 1), with the comments of read 2 as the
  source; GitHub's record showed no CVE id for any of the six on 2026-11-15, and an id GitHub
  assigns after that day is in the advisory itself; the CVE id of an advisory published after
  2026-11-13, if it has one, is in the advisory on the Security tab; and "This page states no
  rule about requesting one."
- `RELEASING.md` step 23 (f): "a CVE is requested from GitHub at the publication when the
  project's owner has said so for the release", where it said "no CVE is requested unless
  `SECURITY.md` names the advisory and says so".
- `RELEASING.md` step 23 (f)(iv): the decision of 2026-11-13 is about the RustSec advisory
  database alone; the request of a CVE from GitHub at an advisory's publication is made when the
  project's owner has said so for the release; a CVE was requested for each of the six
  advisories of 0.8.5 to 0.8.9 at its publication (none with an id on 2026-11-15); an advisory's
  CVE id, where it has one, is in the advisory itself. One clause went with the rule it rested
  on: "so a sitting edits `SECURITY.md` only to name an advisory for which a CVE is requested"
  is now "that page states no rule about requesting a CVE, so a sitting owes `SECURITY.md` no
  edit for its advisory". No other duty of the ritual moved.
- `RELEASING.md` step 14 is unchanged. It never named a CVE, before the lane or after it (the
  lane's diff of the step removes the RustSec second pull request alone), and what it says of a
  patched prerelease, that the edit of the GitHub advisory's range is all the advisory's records
  ask of that sitting, holds whether or not a CVE was requested when the advisory was published.
- `docs/design/843-identity-and-framing.md`, section 9 item 9: the sentence on what the page
  says of a CVE, and one on the class. `CHANGELOG.md`: the entry says what the page and the
  ritual now say. `tests/CLAUDE.md`: the two rows and the summary line.

### A third thing, found by the gate: two rows of one test file

The lane's commit `55b164ce` holds two rows for `arch_ci_lines.rs` in `tests/CLAUDE.md`, the
older one (23 tests) at line 116 and the lane's (24) at line 118, either side of the row of
`arch_duplicate_versions_104.rs`. That row is not on `1acd0854`, the last base this record names,
and is on `d892e206`, the pull request's base: `beta` added it after the row the lane changed,
and the rebase of the lane's commit onto `d892e206` kept both (on each of `5ad961d7`, `228d4f34`,
`1acd0854` and `d892e206` the file has one row of the stem). `rows_from_sources.py --check`
refuses two rows of one stem, and the Test Suite's plan step runs it, so pull request #1004's
`Test Suite (ubuntu-latest, stable)` failed at that step in 12 s (run 43719961053: "2 rows of the
stem `arch_ci_lines` ... at lines 116 and 118"), the suite never starting. The fold leaves one
row, the lane's with the fold's clause, at the older row's place; against the lane's base the
file's whole change is now three lines for three lines.

### The pins that moved

`tests/front_page.rs`, the lane's test
`the_security_page_says_where_advisories_are_published_and_that_none_is_filed_to_rustsec_849`
(11 tests in the file, as before):

- `SECURITY_PAGE_SAYS_849`: thirteen sentences, nine before. The two on a CVE left it ("A CVE is
  requested for an advisory only where this page names the advisory and says so, and it names
  none"; "No file is sent to the RustSec advisory database and no CVE is requested"). Six came:
  the request for each of the six, the reading of 2026-11-15, the later advisory's id, "This
  page states no rule about requesting one", step 3's pointer, and the heading it points at.
- `CVE_REQUESTED_849`, new: the table's six ids in its order, each with the day of read 1. The
  page's list is built from it; a day moved (two plants), an advisory dropped from the list and
  two changing places are each refused.
- `FORMER_CVE_CLAIMS_849`, new, the three sentences the fold removed, in the form the lane used
  for the claims of the page before #849: `no CVE is requested`, `only where this page names the
  advisory and says so`, `No advisory of this crate has a CVE id` (read so on 2026-11-14, but a
  present tense, of advisories for each of which a CVE was requested; the page gives the dated
  reading of the six in its place). Each planted and refused.
- `STALE_ADVISORY_CLAIMS_849` keeps its six needles, `CVE requested` among them (the page's
  words before #849, every advisory "with a CVE requested"). Its refusal no longer says that
  such a claim "says what is not done since 2026-11-13", which of a CVE request nobody decided;
  it says the wording is the page's until #849.

`tests/arch_ci_lines.rs`, the lane's test
`releasing_publishes_an_advisory_on_the_security_tab_and_files_none_with_rustsec_849` (24 tests
in the file, as before):

- `ADVISORY_RECORD_849`: eleven sentences, seven before. "no CVE is requested unless
  `SECURITY.md` names the advisory and says so" left it. Five came: step 23 (f)'s request on the
  owner's word, point (iv)'s two (the decision is about the RustSec database alone; the six
  requests of 0.8.5 to 0.8.9), and the class's two halves.
- `FORMER_CVE_RULES_849`, new: `no CVE is requested`, `to name an advisory for which a CVE is
  requested`. Three plants (step 23 (f)'s sentence, point (iv)'s, the edit of `SECURITY.md`),
  each refused by its words, in any ritual.
- `STALE_ADVISORY_CLASS_849`, new: `a RustSec entry against this crate`, refused wherever the
  ritual describes a security patch's sitting. The test's sample of `main`'s older ritual, the
  class's older line alone, still answers no refusal (the assertion the lane wrote, kept), and
  the same line beside the tip's ritual answers one.
- `STALE_ADVISORY_DUTIES_849` keeps its seven needles; its refusal now says "no standing duty
  of a sitting" where it said "what is not done".

### RED

One scratch tree (`git archive 55b164ce`, under this lane's out folder) and one scratch target
dir, removed after.

- The pins on the lane's commit, the two test files overlaid and no document
  (`SECURITY.md` and `RELEASING.md` there the base's by SHA-256):
  `tests/front_page.rs` 1 of 11 failing with ten refusals (six sentences absent; the three
  removed claims at `SECURITY.md:41` and `:67`; the list of the six days absent);
  `tests/arch_ci_lines.rs` 1 of 24 failing with eight refusals (`no CVE is requested` and `to
  name an advisory for which a CVE is requested` at `RELEASING.md:55`; `a RustSec entry against
  this crate` at `:40`; five sentences absent). Logs `red1-front_page.log`,
  `red1-arch_ci_lines.log`.
- The older sentence put back on the tip, one at a time, the scratch tree's four files the
  tip's and both tests green there before the plants:

  | Put back | Test | Result |
  |---|---|---|
  | the class's sentence at `RELEASING.md:40` | `arch_ci_lines` | 1 of 24 failing, three refusals (the older wording; the class's two halves absent) |
  | step 23 (f)'s "no CVE is requested unless ..." | `arch_ci_lines` | 1 of 24 failing, two refusals |
  | point (iv)'s clause on a CVE and the edit of `SECURITY.md` | `arch_ci_lines` | 1 of 24 failing, four refusals |
  | step 3's "and no CVE is requested" | `front_page` | 1 of 11 failing, two refusals |
  | the page's two sentences on a CVE in the place of `### CVE ids` | `front_page` | 1 of 11 failing, eight refusals |

  Logs `red2-arch_ci_lines-<plant>.log`, `red2-front_page-<plant>.log`; the helper that puts
  each sentence back from `55b164ce`'s own text is `helpers/plant.py` in the out folder.

### The gate

On the Studio (macOS), one cargo at a time, `CARGO_BUILD_JOBS=2` (the host's swap sat above
half: 3.5 of 5.1 GB), a lockfile resolved as CI resolves one (`cargo generate-lockfile`, the
file ignored and removed after), a target dir of the fold's own, removed at the end with the
ratchet's and the scratch tree's. Logs under `/Volumes/Lanes/out/bsv-rs/fix-849-security-page-fold/`.

| Gate | Result |
|---|---|
| Rustfmt, the lint step's three lines, with 1.100.0 (CI's stable) and again with the host's 1.95.0 | clean |
| `cargo +1.100.0 clippy --all-features --locked --test front_page --test arch_ci_lines -- -D warnings` | clean |
| `cargo test --test front_page --locked`, three runs, one single-threaded | 11 passed each run |
| `cargo test --features "full,http" --test arch_ci_lines --locked`, three runs, one single-threaded | 24 passed each run |
| `cargo test --features "full,http" --test 'arch_*' --locked` | 38 binaries, 202 passed, 0 failed, 1 ignored |
| `python3 -B .github/scripts/test_front_pages.py` | 97 tests, OK |
| `python3 -B .github/scripts/rows_from_sources.py --check` and its 10 unit tests | 0 refusals (1 on the lane's commit: the two rows above) |
| `tools/ratchet/run --check --against 55b164ce` | all 7 counters, oversized-file limits and mutation floors pass |
| gitleaks 8.30.1, git mode from the root, `55b164ce..HEAD` | no leaks |

The docs build was not run: no doc comment under `src/` moved (the comments that moved are the
two test files'). The wasm32 build of rule 6 was not run: no file under `src/` changed.

### Not verified by the fold

- That a CVE was requested "from GitHub", and at the moment of publication: read 3 above.
- Whether GitHub has assigned an id since the read of 2026-11-15 at 13:43Z.
- The lane's own list ("Not verified", above) stands as it was.
- A Linux or Windows run of the two tests; CI's after the landing.
