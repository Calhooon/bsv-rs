keeper's word first

# OutputListItem writes its BEEF as a base64 string in JSON, which the TypeScript lookup client refuses

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; the parity note of #768 in bsv-rs's CHANGELOG ("a JSON answer Go writes is refused here and in the reference (`beef` no byte array); not filed"). Drafted by the filings-1109 lane on 2026-11-09.

An overlay host that answers a lookup in JSON with go-sdk's `lookup.LookupAnswer` writes each output's `beef` as a base64 string, because the field is a `[]byte` and `encoding/json` encodes a `[]byte` as base64. The TypeScript reference's lookup client reads `beef` only as an array of byte values, so it refuses that whole answer as `Malformed lookup response` and counts the host as failed.

```go
type OutputListItem struct {
	Beef        []byte `json:"beef"`
	OutputIndex uint32 `json:"outputIndex"`
}
```

The reference's normalizer takes an output only when `isByteArray(output.beef)` holds and refuses the answer otherwise (`LookupResolver.ts:327-335`, `:399-404`), and its own type for the field is `beef: number[]`, so the reference's hosts write `"beef":[1,0,190,239,...]`.

Steps to reproduce (read from the code at 2ca481c, not run):

1. `json.Marshal(&lookup.LookupAnswer{Type: lookup.AnswerTypeOutputList, Outputs: []*lookup.OutputListItem{{Beef: []byte{0x01, 0x00, 0xbe, 0xef}, OutputIndex: 0}}})` gives `{"type":"output-list","outputs":[{"beef":"AQC+7w==","outputIndex":0}]}` (Go's documented encoding of `[]byte`).
2. The reference's `HTTPSOverlayLookupFacilitator` on that body: its byte-field repair (`normalizeBRC100ByteFields(output, ['beef', 'context'])`, `LookupResolver.ts:861-863`) reads a number array, a `Uint8Array` or the historical numeric-key object and leaves a string as it is (`wallet/BRC100ByteEncoding.ts:81-86`), then `normalizeLookupOutput` returns `undefined` for `"AQC+7w=="`, `normalizeOutputListAnswer` returns `undefined`, and the facilitator throws `Malformed lookup response` (`LookupResolver.ts:865-866`); the resolver records a failure against the host.
3. bsv-rs's facilitator refuses the same body (`beef` must be a byte array), as the reference does.

Expected: `beef` written as a JSON array of byte values, as the reference writes and reads it (for example through a `MarshalJSON` on `OutputListItem`).

Actual: a base64 string no TypeScript client reads.

Witness: the parity note of #768 in [CHANGELOG.md](https://github.com/Calhooon/bsv-rs/blob/beta/CHANGELOG.md) (the `0.9.0-beta.7` section) and the JSON answer reader in `src/overlay/facilitators.rs` (`parse_json_lookup_answer`), pinned with the #768 refusals.

Pinned reference reading:

- [go-sdk@2ca481c59 overlay/lookup/types.go:18-22](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/overlay/lookup/types.go#L18-L22) (`Beef []byte`), [:37-43](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/overlay/lookup/types.go#L37-L43) (`LookupAnswer`)

Sibling reading: [ts-stack@edf6e03da packages/sdk/src/overlay-tools/LookupResolver.ts:327-358](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/overlay-tools/LookupResolver.ts#L327-L358) (`normalizeLookupOutput`: `!isByteArray(output.beef)` returns `undefined`) and [:389-410](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/overlay-tools/LookupResolver.ts#L389-L410) (one bad output refuses the answer).

Requested maintainer action: encode `OutputListItem.Beef` in JSON as an array of byte values, as the reference's lookup answers carry it, so a go-sdk host's JSON answer is read by TypeScript clients.

Evidence status: source-read at the pins in this lane; neither go-sdk nor the reference was run for this draft; step 1 follows from `encoding/json`'s documented rule ("[]byte encodes as a base64-encoded string"). Whether a deployed go-sdk overlay host answers in JSON rather than the binary form was not checked. This draft contains no private-key literal.
