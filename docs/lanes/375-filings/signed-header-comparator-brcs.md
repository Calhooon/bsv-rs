keeper's word first

# BRC-104: name the comparator for the signed headers' "lexicographic" order (code points, or a locale collation)

Repository: bsv-blockchain/BRCs

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "On HTTP token punctuation in a header name" (#369, #448; "BRC-104 ... says lexicographic but names no locale or byte comparator, so the keeper must settle the signed-header profile"; "Theirs: BRCs, filing pending"). Supersedes the short batch-1 draft `signed-header-sort.md`. The keeper's word is asked twice here: whether to file at all, and which reading to propose. Drafted by the filings-older-1110 lane on 2026-11-10.

BRC-104 orders a request's and a response's included headers "lexicographically" by lowercase name before they are signed, without naming the comparator; the TypeScript reference sorts with `localeCompare` and go-sdk with Go's byte comparison. The two orders agree on the names BRC-104's own examples use (letters, digits and `-`), and disagree as soon as a signed `x-bsv-*` header name carries other HTTP token punctuation (`_`, `!`, `.`, `~` and the rest), so a request or response signed by one SDK fails verification in the other.

```ts
// SimplifiedFetchTransport.ts:286, AuthFetch.ts:600
return includedHeaders.sort(([keyA], [keyB]) => keyA.localeCompare(keyB))
```

```go
// auth/authpayload/http.go:350-352
sort.Slice(includedHeaders, func(i, j int) bool {
	return includedHeaders[i].Name < includedHeaders[j].Name
})
```

Steps to reproduce (the reference's transport run under Node 22.18.0 with ICU 77.1, locale en-US, by the linked recorder; go-sdk read from the code at 2ca481c, not run):

1. A response with signed headers `x-bsv-a!`, `x-bsv-a#`, `x-bsv-a-`, `x-bsv-a_`, `x-bsv-a~` among others (case `http_token_punctuation`).
2. The reference signs them in the order `x-bsv-a_`, `x-bsv-a-`, `x-bsv-a!`, `x-bsv-a.`, `x-bsv-a'`, … (its `included_headers`); byte order is `x-bsv-a!`, `x-bsv-a#`, …, `x-bsv-a-`, `x-bsv-a.`, …, `x-bsv-a_`, … .
3. On the BRC-104 alphabet alone (`-`, digits, letters, 1,407 names up to two characters past `x-bsv-`) the two orders are the same (`differing_positions: 0`).

The ask: one sentence in BRC-104 naming the comparator, for example "ordered by the lowercase names' bytes (UTF-8 code units), ascending", which go-sdk already does and which the reference reaches by replacing `localeCompare` with a code-unit compare; or, if the intent is to keep the reference's order, the collation named exactly (ICU root, its options), since `localeCompare` also depends on the host's default locale.

bsv-rs follows the reference's `localeCompare` order today (#369) and would follow the BRC's answer.

Witness:

- [tests/transport_header_collation_369.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/transport_header_collation_369.rs) (`issue_369_wider_http_token_names_use_locale_order_in_the_signed_payload`, `issue_369_lowercase_brc104_byte_order_matches_the_node_measurement`)
- [tests/vectors/transport_header_collation_369.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/transport_header_collation_369.json) (three cases with each signed payload, and the 1,407-name measurement, recorded from the reference)

BRC reading: [BRCs@5119a9b51 peer-to-peer/0104.md:105](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/peer-to-peer/0104.md#L105) ("The **order** of included headers will be lexicographical to ensure matching preimages on both sides."), [:196](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/peer-to-peer/0104.md#L196) and [:209](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/peer-to-peer/0104.md#L209) ("in canonical lexicographic order by lowercase header name").

Implementation readings: [ts-stack@edf6e03da packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts:286](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts#L286), [AuthFetch.ts:600](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/clients/AuthFetch.ts#L600); [go-sdk@2ca481c59 auth/authpayload/http.go:350-352](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/authpayload/http.go#L350-L352).

Existing related filing(s): BRCs #360 (ours, open) asks BRC-103 to name the bytes an auth message's JSON signature covers; this is BRC-104's header order, another sentence. No issue found (`--search "header order"`, `"signed headers"`, `"comparator"`, 2026-11-10). Keep these numbers; confirm their scope before opening a duplicate.

Evidence status: the reference was run by the linked recorder (Node 22.18.0, ICU 77.1) and its signed payloads are the vector; go-sdk source-read at 2ca481c. This draft contains no private-key literal.
