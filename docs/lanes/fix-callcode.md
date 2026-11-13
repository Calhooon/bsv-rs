# Lane fix-callcode (#914): an unknown wallet wire call code in the reference's words

Started from `43ee8c85` (`origin/beta`'s tip on 2026-11-12). The drift census of 2026-11-12, row W1.

## The site, side by side

| Side | Site | Answer to a code outside the enum |
|---|---|---|
| `ts-stack@edf6e03` processor | `packages/sdk/src/wallet/substrates/WalletWireProcessor.ts:276-283`, catch `:2379-2396` | ``throw new Error(`Invalid call code: ${callCode}`)`` before the originator, framed code 1: `01 15 "Invalid call code: 29" 00` |
| `ts-stack@edf6e03` HTTP wire | `HTTPWalletWire.ts:33-40` | the same throw, before any fetch |
| `ts-stack@edf6e03` client | `WalletWireTransceiver.ts:141-154` | `new WalletError(message, code, stack)`, no text compared |
| `ts-stack@5226d0c7` processor | `WalletWireProcessor.ts:287-294`, probe `:309-310` | the same sentence for every code but 29 (the certificate profile, `CertificateWireCompatibility.ts:15`) |
| `ts-stack@5226d0c7` client | `WalletWireTransceiver.ts:126-154`, the test `:142-147` | probes 29; falls back on code 2, or code 1 with exactly `Invalid call code: 29`; rethrows anything else |
| `ts-stack@5226d0c7` HTTP wire | `HTTPWalletWire.ts:41-48` | 29 routed to `/certificateCompatibility` |
| bsv-rs `43ee8c85` | `src/wallet/wire/calls.rs:147-150` | `invalid call code: expected 1-28, got 29`, code 1 |
| bsv-rs tip | `src/wallet/wire/calls.rs` `TryFrom<u8>` | `Invalid call code: N`, code 1 |
| go-sdk@2ca481c | `wallet/substrates/wallet_wire_processor.go:91-92`, `http_wallet_wire.go:46-49` | `unknown call type: %d`, no frame; `invalid call code` |

## RED

On a scratch copy of `43ee8c85` (`git archive` under `$TMPDIR`, the test file and vector overlaid, `CARGO_TARGET_DIR=/Volumes/Lanes/targets/fix-callcode-red`), 4 of 5 RED:

- `every_byte_outside_1_to_28_is_refused_in_the_reference_words_callcode`: `left: Err(WalletError("invalid call code: expected 1-28, got 0"))`
- `the_heads_client_falls_back_on_this_crates_answer_to_its_probe_callcode`: row `base_frame`, `fell_back: false`, the head client's error `invalid call code: expected 1-28, got 29`
- `every_recorded_processor_frame_but_the_heads_29_is_this_crates_callcode`: `pin 00`, `0127696e76...` against `0114496e76...`
- `http_wallet_wire_refuses_call_29_unsent_in_the_pin_words_callcode`: `WalletError("invalid call code: expected 1-28, got 29")`

`the_plain_call_after_the_fallback_is_this_crates_stub_not_the_sentence_callcode` green on both (it states what the fix does not buy: the stub).

## The recorder

```
B=$TMPDIR/fix-callcode
git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C $B/edf6e03
git -C <a bare fetch of bsv-blockchain/ts-stack> archive 5226d0c7 packages/sdk | tar -x -C $B/5226d0c7
(cd $B/<sha>/packages/sdk && bun build mod.ts --target node --format esm --outfile sdk.mjs)
# base frames, on the scratch base:
CALLCODE_OUT=tests/support/wire_call_code_callcode_base_frames.json \
  cargo test --features "wallet,http" --test wallet_wire_call_code_callcode this_crates_answers_callcode -- --ignored --exact
# the vector (Node v22.18.0), the tip's test binary driven live:
node tests/support/wire_call_code_callcode.mjs $B/edf6e03/packages/sdk/sdk.mjs $B/5226d0c7/packages/sdk/sdk.mjs \
  tests/support/wire_call_code_callcode_base_frames.json <tip wallet_wire_call_code_callcode test binary> \
  > tests/vectors/wallet_wire/call_code_callcode.json
```

Two runs byte-identical. The loopback is live: the `tip_live` rows are the head's client against this crate's processor, one child process per request, falling back and failing at `<call> requires a full wallet implementation`.

## Siblings (rule 11)

`git grep` of `packages/sdk/src/wallet` at both commits for a client comparing an error's `message`: one site, the head's `WalletWireTransceiver.ts:145`; the other hits read a message to write or check its type (`HTTPWalletJSON.ts:207`/`:270`, `WalletWireProcessor.ts:2387`/`:2430`). In this crate the one function serves both doors that read a call code (the processor and `HttpWalletWire`).

## Dependents

No match for `invalid call code`, `expected 1-28` or `WalletCall::try_from` in `bsv-wallet-toolbox-rs@a3377ef0`, `bsv-wallet-cli@f4285bfb`, `rust-message-box@08418eca`, `bsv-overlay-cloudflare@2efad2f0`.
