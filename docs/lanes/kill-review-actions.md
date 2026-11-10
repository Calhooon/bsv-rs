# Kill lane: `src/wallet/substrates/http_json/review_actions.rs` (#603)

Base: `origin/beta` at `2356b5813edee3e44e1b73f90a6d04d8ced4fa76` (the worktree's start, equal
to `origin/beta`'s tip after `git fetch origin`). The brief was read at `c96f3c7e`; the file is
unchanged since `2ff81a44`. No `src/` change. Logs under
`/Volumes/Lanes/out/bsv-rs/kill-review-actions/`.

## Why they survived

`read_members` runs `result_values::review` (`review_actions.rs:121`) before `action_result`
(`:122`). That validator (`result_values.rs:95-108,194-215`; `result_values/actions.rs:39-127`;
`scalars.rs:23-41,87-104`) refuses in the same words every txid, send result and `noSendChange`
outpoint `hex32` and `outpoint` would refuse, and bounds send results at 1001 and
`noSendChange` at 100000. Only an accepting edge tells a mutant apart; the #339 vector carried
none.

## The recording

`tests/support/wallet_http_json_review_actions_603.mjs`, `@bsv/sdk` at `ts-stack@edf6e03`
bundled with bun under `$TMPDIR/kill-review-actions/`, Node v22.18.0, a fake `fetch` serving
each body at its status. Two runs byte-identical (sha256 `ece0f5d5...38d8`;
`recorder-run1.log`, `recorder-run2.log`). Nine cases. Large lists are markers both sides
expand (`@sendwith:N`, `@sends:N`, `@reviews:N`, `@change:X:N`); every outcome array past four
entries is `{length, head, tail}` on both sides.

The brief's request R (a signAction with 1000 `sendWith`) is refused by the reference's argument
check: `The sendWith parameter must be at most 999 transaction IDs when the signed transaction
joins the broadcast set` (`validationHelpers.ts:871-874`). A createAction that builds a
transaction is refused the same way (`:792-799`); one with no input and no output builds none
(`isNewTx` false) and admits 1000, its result's txid the 1001st, so cases A and B ride it.
Cases C, D, E are the brief's.

## Kills (`tests/wallet_http_json_review_actions_603.rs`, all from the reference)

Each mutant patched by hand in a scratch copy (`$TMPDIR/kill-review-actions/scratch`, its own
`CARGO_TARGET_DIR`), `cargo test --features "full,http" --test wallet_http_json_review_actions_603 <name>`
RED there and green on the tree (`red.log`, `green-tree.log`):

| Mutant | Test | RED line |
| --- | --- | --- |
| `247:20` `>` to `==` | `a_page_of_1001_send_with_results_is_read_and_1002_refused_603` | `send_with_results_1001: {"error":"Invalid createAction result sendWithResults: expected at most 1001 transaction results"}` |
| `247:20` `>` to `>=` | same | same |
| `247:53` `+` to `*` | same | same |
| `247:53` `+` to `-` | same | same |
| `292:20` `>` to `==` | `a_page_of_1001_review_results_is_read_and_1002_refused_603` | `review_results_1001: {"error":"Invalid wallet error reviewActionResults"}`, `review_results_1002: {"error":"Invalid wallet error reviewActionResults[1000].txid"}` |
| `292:20` `>` to `>=` | same | `review_results_1001: {"error":"Invalid wallet error reviewActionResults"}` |
| `292:53` `+` to `*` | same | same |
| `292:53` `+` to `-` | same | same |
| `269:13` arm `Some("unproven")` deleted | `a_send_with_result_unproven_is_read_603` | `send_with_unproven: {"error":"Invalid signAction result sendWithResults[0].status: expected a supported status"}` |
| `180:20` `>` to `==` | `a_no_send_change_of_100000_outpoints_is_read_and_100001_refused_603` | `no_send_change_100000: {"error":"Invalid createAction result noSendChange: expected at most 100000 entries"}` |
| `180:20` `>` to `>=` | same | same |
| `385:22` `&&` to `\|\|` | `a_competing_txid_of_64_non_hex_or_short_hex_is_refused_at_its_index_603` | `competing_txid_64_non_hex: {"review":{... "competingTxs":[] ...` and `competing_txid_short_hex` the same |

## Equivalent candidates (eight, for three reads)

Each reason rests on `:121` (the shared validator) preceding `:122` (the module's decoding).

- `137:5` `safe_integer` to `true`; `140:43` `&&` to `||`. `read`'s one caller
  (`answer.rs:42-43`) is behind `is_review_body` (`:78-81`: status 400, `code` `as_f64 == Some(5.0)`),
  so `code` is 5.0, safe for the tree and both mutants; a code absent, `"5"` or `5.5` never reaches
  `read` (#137's stated divergence, `tests/wallet_http_json_review_actions_339.rs:377-406`).
- `155:28` `||` to `&&` in `hex32`: both inputs (`:218`, `:263`) passed `scalars::hex(.., Some(32))`
  (`actions.rs:40-42,116-121`), so the text is 64 hex digits and both operands are false.
- `195:9`, `196:9`, `197:9`, `198:9` `||` to `&&`; `198:25` `>` to `<` in `outpoint`: each entry
  passed `parse_outpoint` (`scalars.rs:91-104`, the same five predicates and the `u32` parse) at
  `actions.rs:52-60`; on an admitted text every operand is false (an index is non-empty, so
  `len() < 1` is false too).

## Re-measure

`mutation_args('substrates', 'k/48', files=['src/wallet/substrates/http_json/review_actions.rs'])`
(150 test targets with the new file), `--jobs 1`, `k` from 0 to 47, one after another, each under
ten minutes (`mutants/shard-k-48.cmd` and `.log`). Shard 0/24 ran earlier with the baseline (green:
40 s build, 126 s test, auto timeout 633 s) and passed ten minutes, so it was stopped; the 48
shards ran with `--baseline=skip --timeout 390 --build-timeout 480` added so a shard stays inside
ten minutes.

| Run | Mutants | Caught | Missed | Timeout | Unviable | Score of viable |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2026-11-04 (nightly) | 97 | 65 | 20 | 0 | 12 | 76.47% |
| This lane, 48 shards | 97 | 77 | 8 | 0 | 12 | 90.6% |

The eight missed are exactly the candidates above; no other survivor. `docs/ratchets.json` is
not touched.
