# Lane fix-815-overlay: the overlay bucket (#815), every line answered

The bucket issue #815 holds the findings the reads of 2026-11-09 filed outside
their pull requests' subjects for `overlay`. This lane re-read each line on
`origin/beta` at `2b419d90` (2026-11-14), the reference at `ts-stack@edf6e03`
(`git show edf6e03:packages/sdk/src/overlay-tools/<file>`), and gave each a
fate. Earlier lanes did most of the work: PR #821 (`d708646d`), PR #820
(`0e177106`) and the fold `b36bca93` (`docs/lanes/fix-815.md`).

Counts: 24 lines (4 blocking, 19 after-cut in the body, 1 in a comment):
2 built here, 17 already true, 4 need a decision, 1 not a defect of this
crate.

## The table

| # | The line | Fate | Evidence |
|---|---|---|---|
| B1 | `LookupResolver::query` returns the earliest freeform answer over the aggregate | already true | PR #821, `d708646d`; `src/overlay/lookup_resolver/query.rs:262-285`; `tests/lookup_freeform_precedence_815.rs` |
| B2 | `host_acks` holds only the hosts that succeeded | already true | PR #820, `0e177106`; `src/overlay/topic_broadcaster.rs:318` (`requirements::seeded`) |
| B3 | The all-hosts and any-host requirements' topic lists are not checked at `new` | already true | PR #820; `src/overlay/topic_broadcaster/requirements.rs:57` (`snapshot`) |
| B4 | One failure code where the reference has three | already true | PR #820; `requirements.rs:80-96` |
| A1 | Broadcast topics are checked for the `tm_` prefix alone | already true | `b36bca93`; `topic_broadcaster.rs:136`, `requirements.rs:35` (`canonical_topics`); five `_815` tests of `tests/overlay_ship_requirements_tb.rs` |
| A2 | No STEAK validation | already true | `b36bca93`; `topic_broadcaster/steak.rs:67` (`judge`), called at `topic_broadcaster.rs:285`; `facilitators/steak_body.rs`; `tests/overlay_ship_steak_815.rs`, `tests/overlay_ship_steak_door_815.rs`, `tests/arch_steak_door_815.rs` |
| A3 | No interested-hosts cache or in-flight dedup | already true | `b36bca93`; `topic_broadcaster/cache.rs`; `tests/overlay_ship_interested_hosts_cache_815.rs` |
| A4 | #804's Migration paragraph omits two code moves | already true | `CHANGELOG.md`, the #804 entry's Migration paragraph ("Two codes move with it (#815, the strength read of PR #813)") |
| A5 | The #553 row still calls the SLAP hint skip unported | already true | root `CLAUDE.md`, the #553 row: "ported by #786 (the SLAP admission's row)" |
| A6 | The resolver's hint count is unreachable through `GlobalKVStore` | needs a decision | `src/kvstore/global.rs:81-96`: `with_resolver` takes the resolver by value, no accessor; question 1 below |
| A7 | The hint count carries no host, outpoint or reset | needs a decision | `src/overlay/lookup_resolver.rs:115`, `lookup_resolver/query.rs:45`: one `AtomicU64`; question 2 below |
| A8 | A test dials the default trackers and accepts either result | already true | `tests/overlay_integration_tests.rs:1169`: a scripted `.invalid` tracker, the admitted host asserted (plant P6 of `docs/lanes/fix-815.md`) |
| A9 | A binary aggregated SLAP answer through `find_competent_hosts` has no witness | already true | `tests/lookup_slap_binary_answer_815.rs:53` |
| A10 | A `Content-Length` larger than a `u64` is ignored | already true | `src/overlay/facilitators/answer_body.rs:88` (`assert_declared_length`), called at `facilitators.rs:278` |
| A11 | An honest aggregated answer of many same-block outputs is refused as `maxResponseBytes` | needs a decision | measured here (below): 1,024 outputs of one block sum to 37,455,872 bytes, the 32 MiB bound crossed near 970; question 3 below |
| A12 | The JSON answer is built as a tree before the output count | already true | `answer_body.rs:141` (`count_before_tree`) |
| A13 | Three host-answer readings differ from the reference | two already true, the third needs a decision | the content type `answer_body.rs:73`, the BOM `answer_body.rs:113`; the binary answer's count read canonically, `facilitators.rs:625-627`; question 4 below |
| A14 | bsv-overlay-cloudflare's aggregated writer caps no output count | not a defect of this crate | this crate's client bound is the reference's (#775); the downstream writer read at its `2efad2f0`: `crates/overlay-cloudflare/src/routes.rs:2957-2965` writes `outputs.len()` with no cap. For the overlay captain |
| A15 | A failed requirement carries `txid: Some(..)` where the reference's failure has none | built (stated, pinned) | root `CLAUDE.md`, the #804 row; `a_failed_broadcast_carries_the_txid_the_reference_leaves_out_stated_815`; no behaviour change. Removing the id would be a decision (an answer a caller reads): not recommended |
| A16 | The tb-acks vector's description cites the old reference lines | already true | `tests/vectors/ship_requirements_tb_acks.json:2` reads `:212-216,...,511-512,538-546` (re-recorded by `b36bca93`) |
| A17 | A requirement naming a non-canonical broadcast topic is refused in the requirement's words | already true | `topic_broadcaster.rs:136` runs ahead of the snapshots; the recorded case `not_canonical_named_by_a_requirement_too` |
| A18 | No requirement list of exactly 64 topics, no `RequireAck::None` on a specific host | already true | `tests/overlay_ship_requirements_tb.rs`: `a_requirement_list_of_exactly_64_topics_is_taken_815`, `a_specific_host_with_no_requirement_is_passed_over_815` |
| A19 | `GlobalKVStore`'s freeform arm is unreachable, and no test puts a freeform host beside a list at the consumer doors | built | four door tests (below); the kvstore door's was `b36bca93`'s. The arm stays: the `match` over `LookupAnswer` at `src/kvstore/global.rs:487` is exhaustive by it |
| C1 | No test pins that a tracker's host share is counted after #786's admission filter | already true | `tests/lookup_discovery_779.rs:355` (`a_trackers_share_is_counted_after_admission_815`) |

## Built

**A19, the four doors.** `tests/support/pushdrop_lock_position_537.rs` gains
`answering_beside_freeform(service, script, door)`: two hosts for the service
(`https://freeform.<door>-815.invalid` ranked ahead, answering freeform;
`https://list.<door>-815.invalid` answering the script's output). The tests:

- `a_freeform_host_beside_a_list_reads_the_token_at_the_identity_door_815` (`tests/identity_envelope_544.rs`)
- `a_freeform_host_beside_a_list_revokes_the_token_at_the_revocation_door_815` (`tests/identity_revocation_checks_327.rs`, the file's own by-host facilitator)
- `a_freeform_host_beside_a_list_resolves_the_definition_at_the_registry_door_815` (`tests/registry_envelope_544.rs`)
- `a_freeform_host_beside_a_list_names_the_host_at_the_storage_door_815` (`tests/storage_advertisement_envelope_544.rs`)

They pin landed behaviour, so they are green on the base. RED: a scratch
copy of the tree (the tracked files, under this lane's out folder; target
`/Volumes/Lanes/targets/fix-815-overlay-red`, removed) with one plant in
`src/overlay/lookup_resolver/query.rs`, the freeform arm of the merge
returning `Ok(LookupAnswer::Freeform { result })`: 4 of 4 RED (`left: (0, 0)`;
`left: Err(IdentityError("Failed to get lookup result"))`; `left: 0`;
`left: []`).

**A15, the txid.** `a_failed_broadcast_carries_the_txid_the_reference_leaves_out_stated_815`
(`tests/overlay_ship_requirements_tb.rs`); the sentence in the root
`CLAUDE.md`'s #804 row and the CHANGELOG's parity note. A stated cell: green
before and after, no RED to watch.

**The fold (lane fix-815-overlay-fold, the strength read of PR #982).** The
row says every failure and the test held four of the seven sites. Three cases
added, each hermetic (an injected resolver on an `.invalid` host of its own,
a scripted facilitator that counts what it is sent):

| The failure | The reference at `ts-stack@edf6e03` `SHIPBroadcaster.ts` | The case | RED (a scratch copy, `txid: None` planted) |
|---|---|---|---|
| `ERR_NO_HOSTS_INTERESTED` | `:472-478`, returned, `No ${networkPreset} hosts are interested in receiving this transaction.` | the stated test, the `ls_ship` host answering an empty output list: the code, the words, the txid, nothing sent | `topic_broadcaster.rs:236`: `left: None` at the test's txid line |
| `ERR_BEEF_SERIALIZATION` | `:464-470`, thrown, no failure object | the stated test, an output of 2^53 satoshis: the code, the description's opening sentence, the txid, nothing sent | `:200`: `left: None` |
| `ERR_HOST_DISCOVERY` | `:471` awaiting `:743`'s throw, no failure object | `a_failed_discovery_fails_the_broadcast_with_its_txid_stated_815` (`tests/overlay_ship_interested_hosts_cache_815.rs`), 257 outputs: the code, the discovery's error as the description, the txid, one lookup, nothing sent | `:227`: `left: None` |

`ERR_ALL_HOSTS_REJECTED` (`:500-507`) and the three requirement codes
(`:572`, `:596`, `:615`) were held already. No `src/` file changed.

**The second fold (lane fix-815-overlay-fold2, the re-read of PR #982).** The
BEEF case said the lookup is never asked and held it by nothing: its resolver
answered two hosts, so a writer run late answered the same code. The case now
takes a resolver whose `ls_ship` host answers no host, behind a scripted
facilitator that counts its questions, and asserts the count is 0, as the
reference serializes (`:464-470`) before it asks (`:471`). The no-host case
runs under the mainnet and the testnet preset, one lookup each (the local
preset asks no `ls_ship` and holds its one host, so it never answers that
code). Plants, each on a scratch copy, tests alone changed:

| The plant | The result |
|---|---|
| B1: `to_beef` after the lookup and the empty-hosts check | RED: `left: "ERR_NO_HOSTS_INTERESTED"`, `right: "ERR_BEEF_SERIALIZATION"` |
| B1': `to_beef` after the lookup, before the empty-hosts check | RED on the count: `left: 1`, `right: 0` (it passes with the empty resolver alone, run) |
| the empty-hosts check moved after the sends, before the all-rejected check | passes: no host means nothing is sent and nothing read, so no answer differs |
| the empty-hosts check moved after the all-rejected check | RED in both files: `left: "ERR_ALL_HOSTS_REJECTED"` |
| a failed discovery read after the empty-hosts check | RED: `left: "ERR_NO_HOSTS_INTERESTED"`, `right: "ERR_HOST_DISCOVERY"` |
| the word `mainnet` in place of the preset's | RED: `left: "No mainnet hosts ..."`, `right: "No testnet hosts ..."` |

No `src/` file changed.

Read on the same path and not built (two differences older than #815, for the
bucket's decision, question 5 below): the description of
`ERR_BEEF_SERIALIZATION` carries the writer's error after the reference's
sentence (`...BEEF format: <error>` here, `...BEEF format.` there); and a
transaction whose `OffChainValues` metadata is not an array of bytes is sent
without off-chain values here (`topic_broadcaster.rs:209-212`), where the
reference throws `Transaction off-chain values must be a dense byte array.`
before anything is sent (`:457-462`).

Commits: one for both lines (they share `tests/CLAUDE.md` and the CHANGELOG
entry).

## The measurement for A11

A scratch test (kept as `probe_same_block.rs` in the lane's out folder, not
in the tree): N transactions of one input and one 100-byte output, all proven
by one compound BUMP of one block, merged in one BEEF; the sum of
`Beef::to_binary_atomic` over every txid, which is what
`facilitators/binary_answer.rs` counts against `max_response_bytes`.

| N | the whole BEEF | the sum of the N Atomic BEEFs | per output |
|---:|---:|---:|---:|
| 64 | 12,560 | 152,960 | 2,390 |
| 128 | 25,105 | 584,576 | 4,567 |
| 256 | 50,204 | 2,285,568 | 8,928 |
| 512 | 100,893 | 9,290,240 | 18,145 |
| 1,024 | 202,270 | 37,455,872 | 36,578 |

About 35.7 bytes per output per output: 32 MiB (33,554,432) is crossed near
970 same-block outputs of this size, where the issue estimated 330. The
answer's own bytes at 1,024 are 202 KiB. `max_outputs` is 4,096, so an honest
answer of 970 to 4,096 small same-block outputs is refused as
`maxResponseBytes` (neutral for the host, read as an empty answer).

## The questions that need a decision

1. **A6, the kvstore's hint count.** Should a `GlobalKVStore` caller be able
   to read `LookupResolver::txid_hint_contradictions`? Ways: (a) a delegating
   `GlobalKVStore::txid_hint_contradictions(&self) -> u64`, as `IdentityClient`
   has; (b) an accessor lending the resolver; (c) `with_resolver` taking an
   `Arc`, a breaking signature; (d) nothing. Each of (a) and (b) is an
   additive public item (rule 13's reads). Recommendation: (a), the smallest
   surface, after question 2 settles what the count is.
2. **A7, what the hint count carries.** One cumulative number per resolver,
   no host, no outpoint, no reset. Ways: (a) keep the number; (b) a per-host
   record read by a new public door (a `Vec` of host and count, or a drain);
   (c) charge the host's reputation, which the reference does not. (b) is a
   public shape, (c) moves host ranking, an answer a caller sees. The issue
   asks the keeper's word. Recommendation: (b) as a count per host read
   without reset, additive, decided by design reads; never (c) without the
   owner's word, as the reference leaves reputation untouched at the merge.
3. **A11, the same-block answer.** The bound is the reference's own verdict
   (`LookupResolver.ts:929-932`) and this crate conforms; measured, it refuses
   an honest aggregated answer of about 970 or more small outputs of one
   block. Ways: (a) keep parity and tell the downstream writer to page under
   it; (b) count the answer's bytes as received, a stated divergence; (c)
   raise the default `max_response_bytes`. Recommendation: (a) now, with the
   figure handed to the overlay captain beside A14, and the measurement
   offered upstream; (b) and (c) change a verdict against the reference.
4. **A13, the binary answer's count.** This crate reads the count as a
   canonical varint and refuses another form as a host failure
   (`facilitators.rs:625-627`); #815 raises the count's reading at this site
   as an open question for this crate. Ways: (a) keep the canonical read and
   state the row; (b) read
   the count leniently at this one site. Recommendation: (a): every reader of
   this crate is canonical since 0.6.0 and no honest host writes the longer
   form; whether a row is stated at all, and its wording, is the captain's,
   under the rule for what the public tree may say of another implementation's
   reading of outside bytes.
5. **The broadcast's two unstated differences (the fold's read of the
   path).** (i) `OffChainValues` metadata that is not an array of bytes: sent
   without off-chain values here, refused by the reference before any lookup
   (`SHIPBroadcaster.ts:457-462`). Ways: (a) refuse it as a `BroadcastFailure`
   in the reference's words (a caller's malformed metadata now fails where it
   was sent, a behaviour change); (b) state the row. (ii) the
   `ERR_BEEF_SERIALIZATION` description's suffix. Ways: (a) the reference's
   sentence alone (an error text a caller may match); (b) state it.
   Recommendation: (i)(a), since a caller who set the values means them sent,
   and (ii)(b); neither built here.

## The gate

In the foreground on `789d54d6`'s tree, target
`/Volumes/Lanes/targets/fix-815-overlay` (removed after), `origin/beta` still
`2b419d90` at the end: the three Rustfmt lines of `ci.yml`'s lint job;
`cargo +1.100.0 clippy --all-targets --all-features -- -D warnings`;
`cargo check --all-targets --all-features`; the 24 test binaries touched or
sharing the changed support module (every `mod lock_position` file, the
revocation, the requirements, the kvstore door and the freeform precedence
files) three times, once with `--test-threads=1`: 172 passed, 0 failed, 1
ignored each time; `--test 'arch_*' --test fixtures_replay --test
readme_examples`: 36 binaries, 176 passed; `RUSTDOCFLAGS=-Dwarnings cargo doc
--no-deps --all-features`; `tools/ratchet/run --check --against origin/beta`
(a target of its own, removed); `mutants_entries.py` (28 entries);
`rows_from_sources.py --check` (0 refusals); gitleaks in git mode over
`origin/beta..HEAD` (no leaks). No `src/` file changed, so the wasm32 build of
rule 6 was not owed and no unit module was touched. Not run: the whole suite
(one suite run per ensemble is the cold read's).
