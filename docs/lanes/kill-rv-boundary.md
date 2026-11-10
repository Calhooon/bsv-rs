# Kill lane: `src/wallet/substrates/result_values/boundary.rs` (#603)

Base: `origin/beta` at `2356b5813edee3e44e1b73f90a6d04d8ced4fa76` (the worktree's start, equal
to `origin/beta`'s tip after `git fetch origin`). The brief was read at `c96f3c7e`; the file is
unchanged since `2ff81a44`, so every survivor stands at the run's line. Logs under
`/Volumes/Lanes/out/bsv-rs/kill-rv-boundary/`.

## The record

`docs/census/mutants-2026-11-04.md:517-529`: 39 caught, 11 missed, 0 timeout, 1 unviable,
78.00% of 50 (floor 78).

## The recording

`tests/support/http_json_boundary_603.mjs` on the pattern of
`tests/support/http_json_result_values_408.mjs`: the unmodified SDK built from
`ts-stack@edf6e03` (`git archive` then `bun build mod.ts`), Node v22.18.0, the reference's
`HTTPWalletJSON` on an injected fetch whose body is a `ReadableStream` of the recipe (`prefix`,
then `padByte` to `length`, 1 MiB chunks of one reused buffer), and
`snapshotWalletResultRequest` for the request cases. Seven cases, two runs byte-identical
(`cmp`), written to `tests/vectors/http_json_boundary_603.json`:

| Case | Reference |
| --- | --- |
| `content_length_list` | `HTTPWalletJSON response has an invalid Content-Length` |
| `exact_cap_declared` | accepted, height 1 |
| `exact_cap_chunked` | accepted, height 1 |
| `one_past_cap_chunked` | `HTTPWalletJSON response exceeds the maximum permitted size` |
| `unsafe_key_in_outputs` | `Wallet result request records must contain only safe string keys` |
| `labels_at_bound` | accepted |
| `labels_past_bound` | `Wallet request arrays must have a bounded own length` |

hyper resolves to 1.12.0 in the lane's lockfile; its client reader
(`src/headers.rs:76-99`, `content_length_parse_all_values`) accepts a list of equal values, so
`12, 12` reaches `response.headers()` (the brief cited 1.10.1's `:45-70`).

## Kills

All ten from the reference's recordings (source (a)); crate-contract pins: 0.

| Mutant | Killing test | RED (`red-<line>-<col>-<op>.log`) |
| --- | --- | --- |
| `113:13` delete `Value::Array` arm | `an_unsafe_key_inside_a_request_array_is_refused_603` (unit) | `left: None`, `right: Some("Wallet result request records ...")` |
| `121:5` body `Ok(())` | `a_request_array_is_bounded_at_one_million_entries_603` (unit) | `left: None`, `right: Some("Wallet request arrays ...")` |
| `121:49` `>` to `==` | same | `left: Some("Wallet request arrays ...")`, `right: None` (at the bound) |
| `121:49` `>` to `>=` | same | the same |
| `137:39` `&&` to `\|\|` | `a_content_length_list_is_refused_as_invalid_603` | `left: Err("... exceeds the maximum permitted size")` |
| `141:53` `>` to `>=` | `a_body_of_exactly_the_cap_is_read_603` | `left: Err("... exceeds ...")`, `right: Ok(1)` |
| `151:24` `>` to `>=` | the exact-cap pair | both `left: Err("... exceeds ...")` |
| `151:24` `>` to `==` | the exact-cap pair | both `left: Err("... exceeds ...")` (the one-past test passes on it) |
| `151:36` `-` to `+` | `a_chunked_body_one_past_the_cap_is_refused_603` | `left: Ok(1)` |
| `213:15` `>` to `>=` | `a_wire_response_of_exactly_the_cap_passes_and_one_more_is_refused_603` (unit) | panic at the exact-cap `is_ok` |

Each RED in one scratch copy (`$TMPDIR/kill-rv-boundary/scratch`, its own target
`target-red`), the operator patched by hand on a copy of the file and restored after each run,
the killing test run alone. GREEN on the tree: `green-integration.log` (4 passed; about 2.2 s
per exact-cap test, 54 ms for the one-past refusal; 1,361,215,488 bytes peak resident for the
binary under `/usr/bin/time -l`), `green-unit.log` (3 passed).

## The equivalent candidate: `185:33`

The guard `n.is_f64()` to `true` in `normalize_numbers` sends integer `Number`s through `f64`:
identical up to 2^53, rounded above. The function runs only on the fallback of
`http_json/answer.rs:94-106`, after `result_values::validate` (`answer.rs:88`). Every integer
field a typed result reads, with its bound before the fallback:

| Field | Type | Bound |
| --- | --- | --- |
| listActions `actions[].satoshis` | `i64` | -2.1e15 to 2.1e15, `lists.rs:70-75` |
| listActions inputs' `sourceSatoshis` | `u64` | 0 to 2.1e15, `lists.rs:180-184` |
| listActions outputs' `satoshis` | `u64` | 0 to 2.1e15, `lists.rs:251-255` |
| listOutputs `outputs[].satoshis` | `u64` | 0 to 2.1e15, `lists.rs:357-361` |
| the four totals | `u32` | 0 to 2^53 - 1, `lists.rs:17`, then the type |
| `version`, `lockTime`, `sequenceNumber`, `outputIndex` | `u32` | `u32::MAX` (`UINT`, `lists.rs:7`, `:111`) |
| getHeight `height` (`http_json.rs:365`, `u64`) | `u64` | 1 to `u32::MAX`, `scalars.rs:154` |
| `proofType`, protocol level | `u8` | 255 and 2, `scalars.rs:244-247` |
| discovery `trust` | `u8` | 1 to 10, `certificates.rs:215-220` |

`scalars.rs:51-64` reads every bounded integer through `f64`, so no value above 2^53 passes as
exact. A member outside the type is dropped by the typed read; byte fields are normalized and
judged 0 to 255 before. The reference's `JSON.parse` rounds such a number as the mutant does, so
no recording separates them. Stated, not declared in `.cargo/mutants.toml`.

## The re-measure

`mutation_args("substrates", "k/17", ["src/wallet/substrates/result_values/boundary.rs"])`
(152 selected binaries, the new `wallet_http_json_boundary_603` among them,
`selection.log`), `--jobs 1` added, `CARGO_BUILD_JOBS=4`. The baseline ran green under shard
0/10 (`shard-0-of-10.log`: 30 s build, 135 s test) before that split proved too coarse for ten
minutes; shards 0/17 to 16/17 then ran with `--baseline=skip --timeout 300` (or 280), each in
the foreground under a process-group bound, between 60 s and 300 s (`remeasure/times.log`);
shards 3 and 10 were cut at a 290 s bound and rerun whole.

| Caught | Missed | Timeout | Unviable | Score |
| ---: | ---: | ---: | ---: | ---: |
| 49 | 1 (`185:33`) | 0 | 1 (`161:5`, `too_large` with `Default::default()`) | 98.00% |

`docs/ratchets.json` `mutation_floors` untouched.
