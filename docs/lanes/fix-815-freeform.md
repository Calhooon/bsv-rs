# Lane fix-815-freeform: a freeform answer from one host no longer blanks a lookup

Started from `71202e33` (`origin/lane/fix-775`, PR #801's head: beta
`c96f3c7e` plus #775/#785's lookup bounds and host order). The overlay
bucket's BLOCKS-CUT line 2 (`/Volumes/Lanes/out/bsv-rs/captain-notes/buckets-1109/bucket-overlay.md`).

## The site, side by side

The reference, `ts-stack@edf6e03` `packages/sdk/src/overlay-tools/LookupResolver.ts`:

```
1085:  recordFreeformAnswer(): void {
1086:    if (!this.closed) this.freeformHosts++
1087:  }
1123:  snapshot(isFinal: boolean): LookupAnswerProgress {
1124:    return {
1125:      type: 'output-list',
1126:      outputs: Array.from(this.outputsMap.values()),
1374:    return (await this.queryDetailed(question, timeout, options)).answer
1445:    return {
1446:      answer: {
1447:        type: 'output-list',
1448:        outputs: progress.outputs
1449:      },
1501:    if (isOutputListAnswer(answer)) {
1502:      session.recordOutputAnswer(answer)
1510:      return
1511:    }
1512:    session.recordFreeformAnswer()
2399:    // A valid freeform response is neutral: it proves this request reached the
2402:    if (isFreeformAnswer(normalizedAnswer)) return normalizedAnswer
```

Every path of the reference's `query` (`:1369-1375`) returns
`queryDetailed`'s answer, and `queryDetailed` (`:1390-1451`) has one return,
an output list (`:1445-1450`), its other exits throw (an abort, `:1431`; no
host, `:1437-1443`). No path returns a freeform answer. A freeform host is
neither a success nor a failure for its reputation (`:2399-2402`), as this
crate already had it (#760).

This crate before #815 (`src/overlay/lookup_resolver/query.rs`): the merge
ran on every output list, then `if let Some(freeform) = first_freeform {
Ok(freeform) }` returned the earliest freeform answer (rank order) over it.
Since #815: the freeform arm contributes nothing and the answer is the merged
output list, empty when no host answered one.

Go at `2ca481c` (`overlay/lookup/resolver.go:122-124`) returns a freeform
answer when the response first in its channel is one: a stated row, not filed.

## The recording

```
W=/Volumes/Lanes/out/bsv-rs/fix-815-freeform/ref
git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
printf "export * from './packages/sdk/mod.js'\n" > "$W/entry815.ts"
(cd "$W" && bun build entry815.ts --target node --format esm --outfile "$W/ref815.mjs")
cargo test --features overlay --test lookup_freeform_precedence_815 emit -- --ignored --nocapture
~/.nvm/versions/node/v22.18.0/bin/node tests/support/lookup_freeform_precedence_815.mjs \
  "$W/ref815.mjs" input815.json > tests/vectors/lookup_freeform_precedence_815.json
```

Seven shapes, two runs byte-identical. Every shape's answer is
`output-list` from `queryDetailed` and from `query`; the freeform hosts carry
`[0, 0]` successes and failures in the resolver's tracker, every output-list
host `[1, 0]` (empty or not). Ranking a host gives it a tracker entry in the
reference, so the counts, not the entry's presence, are recorded.

## RED

On a scratch copy of `71202e33` (`git archive`, the two test files and the
vector overlaid, `CARGO_TARGET_DIR=~/bsv/targets/fix-815-scratch`):
`lookup_freeform_precedence_815` 6 of 6 RED (`left: Object {"type":
String("Freeform")}`), `overlay_ship_discovery_804 _815` 2 of 2 RED
(`Err(OverlayError("SHIP answer is not a bounded output list."))`).

## What moved in the older pins

- `tests/overlay_ship_discovery_804.rs`: `an_answer_that_is_no_output_list_refuses_the_discovery_804`
  became `a_freeform_ls_ship_host_admits_no_host_and_refuses_nothing_815`;
  the recorded `not_output_list` case (the reference's stub resolver handing
  the reader a freeform answer) replays as no host, its refusal pinned at the
  reader (`src/overlay/topic_broadcaster/discovery.rs`,
  `a_freeform_answer_handed_to_the_reader_is_refused_815`).
- `tests/overlay_mock_tests.rs`: `test_lookup_resolver_with_mock` and
  `test_lookup_resolver_multiple_hosts` assert the empty output list.
- `tests/lookup_tracker_accounting_762.rs`: the resolver half of
  `a_freeform_answer_with_a_null_result_is_an_answer_762` asserts the empty
  output list; the facilitator half unchanged.

## Callers (the migration)

In this crate no caller depended on a freeform answer from `query`
(`GlobalKVStore`'s freeform arm and the identity, registry and storage
readers' non-list arms read nothing, as an empty list does). In the
dependents read (`~/bsv/bsv-overlay-cloudflare`, `~/bsv/bsv-wallet-toolbox-rs`,
`~/bsv/bsv-wallet-cli`, `~/bsv/rust-message-box`), none reads one from
`LookupResolver::query`: overlay-cloudflare's `LookupAnswer::Freeform`
matches are its lookup services' and engine's answers, and the toolbox's
`parse_overlay_answer` maps any non-list answer to no certificate.
