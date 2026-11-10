keeper's word first

# parseBinaryLookupAnswer allocates from an unbounded outpoint count and truncates an output index past 32 bits

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "The lookup client's limits (#775, #785)" ("go-sdk@2ca481c ... casts a binary output index past `0xffffffff` to its low 32 bits"; "Theirs: go-sdk, not filed"). Drafted by the filings-1109 lane on 2026-11-09.

Any overlay host can stop a go-sdk lookup client with a nine-byte answer: an `application/octet-stream` body whose leading VarInt is `ff ffffffffffffffff` makes `parseBinaryLookupAnswer` call `make([]outpointMeta, 0, nOutpoints)` with a capacity of 2^64-1, which panics before a single outpoint is read. A host can also name output `2^32 + 1` and have go-sdk read it as output 1 of the transaction, where the reference refuses the answer.

```go
nOutpoints, err := r.ReadVarInt()
...
metas := make([]outpointMeta, 0, nOutpoints)
...
outputIndex, err = r.ReadVarInt()
...
	outputIndex: uint32(outputIndex), //nolint:gosec // G115 -- output index bounded by transaction output count
```

The `nolint` comment's premise does not hold: nothing compares the index with the transaction's output count before the cast. The reference bounds the count before it reads (`if (!Number.isSafeInteger(nOutpoints) || nOutpoints < 0 || nOutpoints > maxOutputs) throw new LookupResourceLimitError('maxOutputs')`, `LookupResolver.ts:877-883`) and refuses the index (`if (outputIndex > 0xffffffff) throw new Error('Overlay output index is out of range.')`, `:888`).

Steps to reproduce (read from the code at 2ca481c, not run):

1. A lookup host answers `200 OK`, `Content-Type: application/octet-stream`, body `ffffffffffffffffff`. `HTTPSOverlayLookupFacilitator.Lookup` reaches `parseBinaryLookupAnswer`, and `make` panics (`makeslice: cap out of range`). A count such as `ff 0000000000010000` (2^40, the VarInt's eight bytes little-endian) asks for tens of terabytes instead. The reference throws `LookupResourceLimitError('maxOutputs')` on both.
2. A body of one outpoint `01`, a 32-byte txid `T`, the index `ff 0100000001000000` (2^32 + 1), a context length `00`, then a BEEF holding `T`. go-sdk answers `{outputIndex: 1}` for `T`; the reference throws `Overlay output index is out of range.`.

Expected: the count bounded (by the bytes remaining, at 41 bytes per outpoint at least, or by a configured output limit) before the allocation, and an index above `0xffffffff` refused.

Actual: a panic on the count, and a silent truncation of the index.

bsv-rs refuses both in the reference's words since #775 (`parse_binary_lookup_response` in `src/overlay/facilitators.rs`: the count above `max_outputs` refused before any outpoint is read, the index past `u32` refused as `Overlay output index is out of range.`).

Witness:

- [tests/lookup_limits_775.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/lookup_limits_775.rs) and [tests/lookup_limits_configured_775.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/lookup_limits_configured_775.rs) (the binary reader's output count and index refusals)

Pinned reference reading:

- [go-sdk@2ca481c59 overlay/lookup/facilitator.go:83-131](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/overlay/lookup/facilitator.go#L83-L131) (the count at `:86-96`, the cast at `:128`), reached from `Lookup` at [:60-62](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/overlay/lookup/facilitator.go#L60-L62)

Sibling reading: [ts-stack@edf6e03da packages/sdk/src/overlay-tools/LookupResolver.ts:871-900](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/overlay-tools/LookupResolver.ts#L871-L900) (`parseOctetStreamLookup`).

Existing related filing(s): go-sdk #407 (row 19 of the queue: `decodeOutpoints`' `make(..., 0, count)` from an unbounded wire count in the wallet serializer, the same pattern at another site) and go-sdk #400 (the wallet wire's collection counts). Keep these numbers; confirm their scope before opening a duplicate. Not asked here: the reference's 32 MiB response and 1 MiB context bounds, its own resource safeguards rather than a protocol rule.

Requested maintainer action: bound `nOutpoints` by the bytes remaining before `make`, and refuse an output index above `0xffffffff` instead of casting it.

Evidence status: source-read at the pins in this lane; go-sdk was not run; the panic is Go's documented behavior for a `make` capacity past the allocator's limit. This draft contains no private-key literal.
