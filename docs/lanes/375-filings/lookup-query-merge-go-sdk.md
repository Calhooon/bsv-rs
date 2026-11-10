keeper's word first

# LookupResolver.Query returns a lone freeform answer over every other host's outputs, lets a later copy of an outpoint replace the earlier, and returns the outputs in map order

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "The resolver's merge reads a lookup output's `txid` hint (#796)" ("Go ... keeps a later copy") and the parity note of #815 ("Theirs: go-sdk, not filed"). Drafted by the filings-1109 lane on 2026-11-09.

When a go-sdk `LookupResolver` asks several overlay hosts and the host whose answer reaches the channel soonest answers `freeform`, `Query` returns that freeform answer and drops every other host's output list, so a kvstore, registry or identity lookup comes back empty because of one host. When two hosts return the same outpoint, the copy from the host that answered later replaces the earlier one, and the merged outputs come back in Go map iteration order, a different order on every call.

```go
if successfulResponses[0].Type == AnswerTypeFreeform {
	return successfulResponses[0], nil
}

outputsMap := make(map[string]*OutputListItem)
for _, response := range successfulResponses {
	...
	outputsMap[fmt.Sprintf("%s.%d", tx.TxID().String(), output.OutputIndex)] = output
	...
}
for _, output := range outputsMap {
	answer.Outputs = append(answer.Outputs, output)
}
```

The reference answers the merged output list on every path (`query` returns `queryDetailed(...).answer`, `LookupResolver.ts:1374`, built as `{ type: 'output-list', outputs: progress.outputs }` at `:1445-1450`; a freeform host is counted, `:1085-1087`), keeps the earliest copy of a key (`if (this.outputsMap.has(key)) continue`, `:1107`) and keeps the outputs in the order it merged them (`:1112-1113`). With no host answering, it answers an empty list where go-sdk returns `no-successful-responses` (`resolver.go:118-120`).

Steps to reproduce (read from the code at 2ca481c, not run):

1. Two hosts for `ls_example`: host A answers `{"type":"freeform","result":{}}` quickly, host B answers an output list with one output. `Query` returns A's freeform answer; the reference returns B's output.
2. Two hosts answer the same outpoint `T.0`, host A with context or BEEF bytes `X` and host B, answering later, with `Y`. `Query` returns `Y`; the reference returns `X`.
3. Three hosts answer three distinct outpoints. Calling `Query` repeatedly returns them in varying order (map iteration); the reference returns them in merge order.

bsv-rs answers the merged list as the reference does (the freeform rule on the open PR #821, the earliest copy kept since #796).

Witness:

- [tests/lookup_hint_merge_796.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/lookup_hint_merge_796.rs) and [tests/vectors/lookup_hint_merge_796.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/lookup_hint_merge_796.json) (the reference's merge recorded under Node 22.18.0: the earliest copy of a key kept)
- `tests/lookup_freeform_precedence_815.rs` and `tests/vectors/lookup_freeform_precedence_815.json` on the open bsv-rs PR #821 (the reference's answer when one host answers freeform, recorded under Node 22.18.0)

Pinned reference reading:

- [go-sdk@2ca481c59 overlay/lookup/resolver.go:111-149](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/overlay/lookup/resolver.go#L111-L149)

Sibling reading:

- [ts-stack@edf6e03da packages/sdk/src/overlay-tools/LookupResolver.ts:1101-1115](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/overlay-tools/LookupResolver.ts#L1101-L1115) (`mergeAnswer`), [:1370-1375](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/overlay-tools/LookupResolver.ts#L1370-L1375) and [:1445-1450](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/overlay-tools/LookupResolver.ts#L1445-L1450) (the answer)

Existing related filing(s): ts-stack #1482 (the reference's own reading of the lookup output's `txid` hint at this merge, which go-sdk's `OutputListItem` does not carry). Keep these numbers; confirm their scope before opening a duplicate.

Requested maintainer action: merge every host's output list whatever another host answered, keep the earliest copy of an outpoint, and return the outputs in a stable order (a slice beside the map), as the reference's merge does.

Evidence status: source-read at the pins in this lane; go-sdk was not run, and the reference's verdicts are the recorded vectors. This draft contains no private-key literal.
