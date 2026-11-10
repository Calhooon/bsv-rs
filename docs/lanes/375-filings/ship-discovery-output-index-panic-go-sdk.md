keeper's word first

# Broadcaster.FindInterestedHosts panics on a SHIP lookup output whose outputIndex is past the transaction's outputs

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "The SHIP discovery's admission (#804)" ("indexing the output unchecked"). Drafted by the filings-1109 lane on 2026-11-09.

Any `ls_ship` lookup host can stop a go-sdk program that broadcasts to an overlay: an output in its answer whose `outputIndex` is not below the transaction's output count makes `Broadcaster.BroadcastCtx` panic with an index out of range, since `FindInterestedHosts` runs in the caller's goroutine with no `recover`. The reference and go-sdk's own SLAP reader skip such an output.

```go
for _, output := range answer.Outputs {
	tx, err := transaction.NewTransactionFromBEEF(output.Beef)
	if err != nil {
		continue
	}
	script := tx.Outputs[output.OutputIndex].LockingScript
```

go-sdk's SLAP reader, a few lines from it, checks the index before it reads (`resolver.go:194-195`, `else if len(tx.Outputs) <= int(output.OutputIndex) { slog.Error("Output index out of range", ...)`); the reference reads `tx.outputs[outputIndex]` and skips `null` (`SHIPBroadcaster.ts:772-773`).

Steps to reproduce (read from the code at 2ca481c, not run):

1. A `Broadcaster` for `tm_example` whose resolver's lookup host answers `ls_ship` with `{"type":"output-list","outputs":[{"beef":<any valid BEEF whose subject has one output>,"outputIndex":1}]}`.
2. `Broadcast(tx)`: `FindInterestedHosts` evaluates `tx.Outputs[1]` on a one-element slice and panics (`runtime error: index out of range [1] with length 1`).

Expected: the output is skipped, as at `resolver.go:194-195` and in the reference.

Actual: a panic out of `Broadcast`.

bsv-rs reads the selected output through a bounds-checked lookup and skips a missing one, as the reference does.

Witness:

- [tests/overlay_ship_discovery_804.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/overlay_ship_discovery_804.rs) and [tests/vectors/ship_discovery_admission_804.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/ship_discovery_admission_804.json) (the SHIP reader as the reference reads it; this crate holds no output index past `u32` and skips a missing output)

Pinned reference reading:

- [go-sdk@2ca481c59 overlay/topic/broadcaster.go:278-283](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/overlay/topic/broadcaster.go#L278-L283) (the unchecked index), called from `BroadcastCtx` at [:126](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/overlay/topic/broadcaster.go#L126)
- [go-sdk@2ca481c59 overlay/lookup/resolver.go:194-195](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/overlay/lookup/resolver.go#L194-L195) (the sibling reader's check)

Sibling reading: [ts-stack@edf6e03da packages/sdk/src/overlay-tools/SHIPBroadcaster.ts:772-773](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/overlay-tools/SHIPBroadcaster.ts#L772-L773) (`const selectedOutput = tx.outputs[outputIndex]; if (selectedOutput == null || selectedOutput.satoshis !== 1) continue`).

Existing related filing(s): the draft `overlay-discovery-advertisement-admission-go-sdk` (the admission rules at the same loop). This one is the crash alone, so it can be fixed on its own. Keep these numbers; confirm their scope before opening a duplicate.

Requested maintainer action: check `int(output.OutputIndex) < len(tx.Outputs)` before reading the output in `FindInterestedHosts`, as `FindCompetentHosts` does, and add a regression with an out-of-range index.

Evidence status: source-read at the pins in this lane; go-sdk was not run. This draft contains no private-key literal.
