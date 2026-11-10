# Kill lane: `src/wallet/wire/processor.rs` (#603)

Base: `origin/beta` at `b681f1fa` (the worktree's HEAD was `origin/beta`'s tip; no reset).
The census is `docs/census/mutants-2026-11-04.json` (`survivors`) and
`docs/census/mutants-2026-11-04.md:119,460-465`: 6 caught, 4 missed, 0 timeout, 31
unviable, 60.00% (floor 60). Logs are under `/Volumes/Lanes/out/bsv-rs/kill-wire-processor/`.

## The gap

All four survivors are deleted match arms in `WalletWireProcessor<W>::invoke_wallet`, each
under `#[cfg(feature = "tracing")]` (`processor.rs:249`, `:260` at the base). The oracle builds
with `--features full,http` (`.github/scripts/nightly_mutants.py:170-171`), and `full` does not
carry `tracing` (`Cargo.toml:196`). The only binary that listens for the events,
`tests/wire_tracing_sink.rs`, is in `APART` (`.github/scripts/affected_tests.py:47`), so
`nightly_mutants.py:152` drops it. A deleted arm in uncompiled text builds and passes, and the
oracle counts it as missed. None of the four is equivalent. In the `tracing` build each one is
observable.

## The sources

- The frame bytes come from the reference's `#invokeWallet` (`ts-stack@edf6e03`
  `packages/sdk/src/wallet/substrates/WalletWireProcessor.ts:2402-2418`): an explicit wallet
  error keeps its code and words (`:2416`), and every other error becomes `Wallet operation
  failed`, code 1 (`:2417`). The reference logs nothing at that site.
- The events are this crate's own addition, so every event assertion is a crate-contract pin
  on `src/wallet/wire/CLAUDE.md`'s sentence: "`invoke_wallet` emits one `warn` event where it
  chooses the constant ...". These kills are counted apart from the reference's.
- Go at `2ca481c` logs nothing here (`wallet/substrates/wallet_wire_processor.go:94-96`).
  BRC-100 is not cited, because it says nothing about logging.

## Step 1: the tracing build

`cargo test --features "wallet,http,tracing" --test wire_tracing_sink` ran in a scratch copy
(`$TMPDIR/kill-wire-processor/scratch`, own target dir) with each arm deleted by hand, one at a
time. Logs: `step1-red-<id>.log`.

| Mutant | Arm deleted | Test | RED line |
| --- | --- | --- | --- |
| `252:25` | `Error::WalletRefusal{class, ..}` (coded) | `a_wallet_refusal_raises_one_event_with_the_call_and_its_class` (existing) | `wire_tracing_sink.rs:200:5` `left: 0, right: 1` (no event) |
| `253:25` | `Error::AbortAccepted(a)` (coded) | `an_accepted_abort_with_a_coded_class_raises_one_event_with_its_class` (new) | `wire_tracing_sink.rs:253:5` `left: 0, right: 1` |
| `263:25` | `Error::WalletRefusal{class, message}` (uncoded) | `an_uncoded_refusal_raises_one_event_with_its_class_and_words` (existing) | `wire_tracing_sink.rs:227:28` `no entry found for key` (`class` absent) |
| `266:25` | `Error::AbortAccepted(a)` (uncoded) | `an_accepted_abort_with_an_uncoded_class_raises_one_event_with_its_class_and_words` (new) | `wire_tracing_sink.rs:282:28` `no entry found for key` |

The two new tests assert three things each. The coded test expects the frame
`070573686f727400` (a, `:2416`) and one `warn` event with `call` `getHeight`, `class`
`WERR_INSUFFICIENT_FUNDS` and the message `wallet refusal framed with its code`, 3 fields (c).
The uncoded test expects the frame `WALLET_OPERATION_FAILED_FRAME` (a, `:2417`) and one event
with `call`, `class` `WERR_UNAUTHORIZED`, the words as `error` and the replacement message,
4 fields (c). On the tree all 9 tests pass (`step1-green-tree.log`, `step2-tracing-tree.log`).

## Step 2: the selection moved where the oracle builds it

`validation.rs` gained `pub(super) fn refusal_record(error: &Error) -> Option<(WalletRefusalClass,
&str)>` beside `explicit_wallet_code`. It is compiled in every build and carries
`#[cfg_attr(not(feature = "tracing"), allow(dead_code))]`. `WalletRefusal` gives its class and
message, `AbortAccepted` gives its record's class and message, and everything else gives
`None`, `WalletReviewActions` included (it raised no kept event before either). Both cfg blocks
of `invoke_wallet` call it through `if let ... else`. No `match` is left there, so no arm mutant
sits in uncompiled text. `processor.rs` fell from 934 to 926 lines. Wire bytes, `Display`,
events and the public API are unchanged.

`cargo mutants --list --file src/wallet/wire/processor.rs --features full,http` lists 37 mutants
(41 at the census) and none in `invoke_wallet`. The three `270:9` entries are
`encode_response`'s return value: they were already listed in the census and are now 8 lines
higher.

The unit test is `validation.rs`'s
`a_refusal_and_an_accepted_abort_carry_their_class_and_words_to_the_event`, a crate-contract pin
quoting `src/wallet/wire/CLAUDE.md`'s sentence. It covers a coded and an uncoded
`WalletRefusal`, an `AbortAccepted`, and `WalletError` and `WalletReviewActions` giving `None`.
It went RED in the scratch copy three times (`step2-red-helper-*.log`):

| Change | RED line |
| --- | --- |
| `WalletRefusal` arm deleted | `validation.rs:366:9` `left: None, right: Some((InsufficientFunds, "short"))` |
| `AbortAccepted` arm deleted | `validation.rs:383:9` `left: None, right: Some((InvalidOperation, "already broadcast"))` |
| body replaced by `None` | `validation.rs:364:9` `left: None, right: Some((InsufficientFunds, "short"))` |

## Re-measure

The selection is `n.mutation_args("wire", "0/1", [<file>])`, printed in `selection.log`. Both
files ran under `cargo mutants --jobs 1` in round-robin shards, each under ten minutes, with a
private `CARGO_TARGET_DIR`.

- `processor.rs` ran in 10 shards (`remeasure-processor-<k>of10.log`), each with its own
  baseline.
- `validation.rs` ran in 15 shards with `--baseline=skip --timeout 750`. The baseline is the
  same tree and had already passed green in all ten processor shards.

| File | Mutants | Caught | Missed | Timeout | Unviable | Score (of viable) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `processor.rs`, census | 41 | 6 | 4 | 0 | 31 | 60.00% |
| `processor.rs`, tip | 37 | 6 | 0 | 0 | 31 | 100.00% |
| `validation.rs`, census | 68 | 23 | 1 | 0 | 44 | 95.83% |
| `validation.rs`, tip | 73 | 26 | 1 | 0 | 46 | 96.30% |

`processor.rs`'s 6 caught are `process_message` and `encode_response` returning `Ok(vec![])`,
`Ok(vec![0])` and `Ok(vec![1])`. Its 31 unviable are `Default::default()` replacements on
`Answer` (no `Default` for `Result<Vec<u8>, Refusal>`) and `wallet()`'s `W: Default`.

The helper's five mutants:

- `97:5` `None`: caught.
- `98:9` `WalletRefusal` arm deleted: caught.
- `99:9` `AbortAccepted` arm deleted: caught.
- `97:5` `Some((Default::default(), ""))` and `"xyzzy"`: unviable, because
  `WalletRefusalClass` has no `Default`.

`validation.rs` has one standing survivor, `261:15` (`>` to `>=` in `result_bytes`). It is the
census's `245:15`, moved down by the 16 helper lines, and it belongs to another lane.

`docs/ratchets.json` `mutation_floors` is not raised: the next complete run records the scores.

## The other way (the captain's or keeper's call)

The alternative is to build the wire oracle with `tracing` and take `wire_tracing_sink` out of
`APART`. That is an oracle change, and with it step 2 would not be needed.
`src/wallet/wire/diagnostics.rs` (0 of 2 at the census, `:113,406-409`) has the same cause: its
two functions exist only under `tracing`. It is out of this lane's scope.
