# Kill lane: `src/wallet/wire/diagnostics.rs` (#603)

Base: `origin/beta` at `4e57b23f53dcf271ed19a34a22c1aeab66fd6789` (the worktree's start, equal
to `origin/beta`'s tip after `git fetch origin`). The brief was read at `c96f3c7e`; the two
survivors stand unmoved at the base (`src/wallet/wire/diagnostics.rs:8-15`, `:18-35`).
Logs under `/Volumes/Lanes/out/bsv-rs/kill-wire-diagnostics/`.

## Why the survivors stood

`mod diagnostics;` sits under `#[cfg(feature = "tracing")]` (`src/wallet/wire/mod.rs:77-78`),
its callers under the same gate (`src/wallet/wire/processor.rs:250-270`), and `tracing` is
outside `full`. The oracle built every surface with `--features full,http`
(`.github/scripts/nightly_mutants.py`, `mutation_args`) and its selection subtracts
`affected_tests.APART`, which holds `wire_tracing_sink`. So each mutant rewrote text no build
compiled: `0s build`, `missed`.

Build witness (`build-witness.log`): a scratch copy with the file's body replaced by
`compile_error!("unbuilt");` builds under `--features full,http --lib` (exit 0) and refuses
under `--features full,http,tracing --lib` (`error: unbuilt`, exit 101).

## Before and after

| Run | Word | Caught | Missed | Timeout | Unviable | Score |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Reproduce, base (`reproduce.log`, shards 0/2 and 1/2) | `full,http`, 151 binaries | 0 | 2 | 0 | 0 | 0.00% |
| Re-measure, tip (`remeasure-0.log`, `remeasure-1.log`) | `full,http,tracing`, 152 binaries | 2 | 0 | 0 | 0 | 100.00% |
| `processor.rs` four arms, tip (`remeasure-proc-{0..3}.log`) | `full,http,tracing` | 4 | 0 | 0 | 0 | 4 of 4 |

Every command printed by the script (`mutation_args("wire", "k/n", [file])`, `--jobs 1`
inserted), in sequence, each under ten minutes. The `processor.rs` rows ran with
`--re '^src/wallet/wire/processor\.rs:(252|253|263|266):25: delete match arm'` in four
round-robin shards; shard 0/4 ran its baseline (green, 224 s test), shards 1/4 to 3/4 ran
`--baseline skip --timeout 600` to stay inside ten minutes, the baseline of the same tree
and word already green in three runs.

## Kills (`tests/wire_tracing_sink.rs`)

Each kill a crate-contract pin, counted apart (reference kills 0): `ts-stack@edf6e03`
`WalletWireProcessor.ts:2402-2419` logs nothing, go-sdk `2ca481c`'s processor logs nothing,
BRC-100 at `5119a9b` names no logging. The line pinned: `src/wallet/wire/CLAUDE.md:85`.

| Mutant | Killing test | RED |
| --- | --- | --- |
| `diagnostics.rs:9:5` `kept` with `()` | `a_wallet_refusal_raises_one_event_with_the_call_and_its_class` | `red-9-5.log`: `events.len()` `left: 0, right: 1` |
| `diagnostics.rs:19:5` `replaced` with `()` | `an_uncoded_wallet_error_raises_one_event_with_the_call_and_the_wallets_words`, `the_event_names_the_call_whose_wallet_refused`, `an_uncoded_refusal_raises_one_event_with_its_class_and_words` | `red-19-5.log`: three tests `left: 0, right: 1` |
| `processor.rs:252:25` delete `Error::WalletRefusal{class, ..}` | `a_wallet_refusal_raises_one_event_with_the_call_and_its_class` | `red-252-25.log`: `left: 0, right: 1` |
| `processor.rs:253:25` delete `Error::AbortAccepted(a)` | `an_accepted_abort_of_a_coded_class_raises_the_kept_event_with_its_class_439` (new) | `red-253-25.log`: `left: 0, right: 1` |
| `processor.rs:263:25` delete `Error::WalletRefusal{class, message}` | `an_uncoded_refusal_raises_one_event_with_its_class_and_words` | `red-263-25.log`: no `class` field (panic at the index) |
| `processor.rs:266:25` delete `Error::AbortAccepted(a)` | `an_accepted_abort_of_an_uncoded_class_raises_the_replaced_event_with_its_class_and_words_439` (new) | `red-266-25.log`: no `class` field |

The `diagnostics.rs` mutants also read `1 caught` each through cargo-mutants under
`--features full,http,tracing --cargo-arg=--lib --cargo-arg=--test=wire_tracing_sink` in a
scratch copy (`red-mutants.log`). GREEN on the tip: 9 passed (`green-sink.log`).

## The oracle's change

`nightly_mutants.py`: `SURFACE_FEATURES = {"wire": "full,http,tracing"}` and
`SURFACE_TESTS = {"wire": ["wire_tracing_sink"]}`, applied in `mutation_args` (the surface
known there; `selection` keys by module and wire and substrates are both `wallet`); a changed
sink re-measures the wire files (`reach`). `affected_tests.APART` unchanged.
`test_603_the_wire_surface_compiles_the_tracing_gated_diagnostics_and_runs_its_sink` RED
before (`['full', 'http']`, `red-oracle-test.log`); the two `test_685_*` tests read the new
truth (the wire's empty selection carries the sink; a changed sink reaches
`src/wallet/wire/mod.rs` alone).

Mutant lists: `cargo mutants --list --file 'src/wallet/wire/**/*.rs'` under `full,http` and
`full,http,tracing`, 793 lines each, `diff` empty (`list-diff.txt`): no wire mutant leaves.
