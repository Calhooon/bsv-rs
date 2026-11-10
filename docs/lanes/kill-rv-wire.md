# Kill lane: `src/wallet/substrates/result_values/wire.rs` (#603)

Base: `origin/beta` at `ebea5ee0d0b6516ae8ba43adb65e7bde8f026ac4` (the worktree's start, equal to
`origin/beta`'s tip after `git fetch origin`). The brief was read at `c96f3c7e`; `wire.rs` is
unchanged since the run's `2ff81a44`. Logs under `/Volumes/Lanes/out/bsv-rs/kill-rv-wire/`.

## The survivors (`docs/census/mutants-2026-11-04.md:110`, `:510-515`)

13 caught, 4 missed, 1 unviable, 76.47% (floor 76).

| Mutant | Why it lived | Killing test | RED |
| --- | --- | --- | --- |
| `43:65` `>` to `==` | no test reached a total above the cap | `a_linkage_whose_byte_fields_total_past_the_cap_is_refused_603` (and the at-cap test) | `red-43-65-eq.log`: 2 of 3 FAILED |
| `43:65` `>` to `>=` | no test reached a total of exactly the cap | `a_linkage_whose_byte_fields_total_the_cap_is_accepted_603` | `red-43-65-ge.log`: 1 of 3 FAILED |
| `207:9` delete `binary` in `linkage` | the total reads 0 and the metadata's `[]` passes the byte rows | `a_linkage_whose_byte_fields_total_past_the_cap_is_refused_603` | `red-207-9-delete-binary.log`: 1 of 3 FAILED |
| `193:13` delete `outputs` in listOutputs | #487 recorded no accepted row with a present matching script | `a_listed_output_whose_script_matches_its_beef_is_accepted_603` | `red-193-13-delete-outputs.log`: `the script committed by BEEF` |

Each mutant applied by hand in a scratch copy under `$TMPDIR` with its own `CARGO_TARGET_DIR`
(the diff at the head of each log), GREEN on the tree.

## The reference (`ts-stack@edf6e03`)

`tests/support/rv_wire_kill_603.mjs` against the bun bundle of `packages/sdk` (an archive, never
a checkout of the clone), Node v22.18.0, writes `tests/vectors/rv_wire_kill_603.json`:

- `total_at_cap` (268,435,455 + 1), `total_past_cap` (268,435,456 + 1), `small_control` (1 + 1):
  `validateWalletResult('revealCounterpartyKeyLinkage', ...)`, accepted, refused (`Invalid
  revealCounterpartyKeyLinkage result byte arrays: expected at most 268435456 total bytes`),
  accepted; `WalletResultValidation.ts:632-637`'s strict `>`. Lengths stored, never bytes.
- `list_outputs_matching_script`: the reference's `WalletWireTransceiver.listOutputs` on #487's
  `listOutputs_valid` frame with `lockingScript` `51`, written by #487's listOutputs writer
  (copied verbatim): accepted. The frame is #487's with the nine-byte absent sentinel
  (`ff` x 9 after `fde803`) becoming `0151`; the brief's `fde803ff` names the sentinel's first byte.

## Below the transceiver, at the processor

Test A (`src/wallet/substrates/result_values/wire_total_603_tests.rs`) calls the crate-internal
`WireResult::check`. Through `WalletWireTransceiver` the three line-43/207 mutants are
unreachable: `transceiver.rs:133` refuses a response over `MAX_BYTES` before decoding
(`boundary.rs:212-219`, the reference's `WalletWireTransceiver.ts:108-132`), and a frame carries
more than its byte fields' sum (read, not run). `WalletWireProcessor` reaches the check: it
validates a wallet's linkage result before encoding it (`processor.rs:447`,
`validation.rs:308-313`), as the reference's processor does (`#invokeValidatedWallet`,
`WalletWireProcessor.ts:2421-2431`, called at `:1752-1756`). The cold read's probe (a wallet
answering 268,435,456 + 1 bytes through `process_message`, refused in these words; 268,435,455 + 1
answered) was RED on each of the three mutants, so they are not equivalent at the door; the
probe is not committed. `WireResult::check` is the Rust form of the reference's exported
`validateWalletResult` (`WalletResultValidation.ts:2179`, exported by
`packages/sdk/src/wallet/index.ts:20`).

Test A's binary, run alone on its three tests: peak resident size 14,090,240 bytes
(`/usr/bin/time -l`); the zeroed 256 MiB slices are never touched.

## Re-measure

`mutation_args('substrates', 'k/9', ['src/wallet/substrates/result_values/wire.rs'])` (152
`--test` targets, `--lib`, the surface's skips; `wallet_wire_result_kill_603` among them),
`--jobs 1`, shards 0 to 8 in sequence in the foreground, each 3 to 6.5 minutes
(`shard-<k>.log`, `shard-<k>/mutants.out/`):

| Caught | Missed | Timeout | Unviable | Score over viable |
| ---: | ---: | ---: | ---: | ---: |
| 17 | 0 | 0 | 1 | 17 of 17 (100.00%) |

The unviable one is `154:9` (`Output::from` with `Default::default()`, a type with no default),
as in the run. No equivalent found. `docs/ratchets.json` untouched.
