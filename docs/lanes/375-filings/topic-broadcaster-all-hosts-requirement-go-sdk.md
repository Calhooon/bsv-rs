keeper's word first

# An all-hosts acknowledgment requirement passes when an interested host failed, because only the successful hosts are checked

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; the parity note of the open bsv-rs PR #820 (the topic broadcaster's acknowledgment requirements: "Theirs: go-sdk, not filed"). Drafted by the filings-1109 lane on 2026-11-09.

A go-sdk user who configures `AckFromAll` (every interested host must acknowledge the topics) and broadcasts to three interested hosts, one of which rejects the transaction or is unreachable, gets `BroadcastSuccess`: the requirement is judged over the hosts that answered successfully, so a failed host is never counted against it. The reference reports `ERR_REQUIRE_ACK_FROM_ALL_HOSTS_FAILED` in the same case.

go-sdk builds the acknowledgment map from the successful responses alone and checks every entry in it:

```go
hostAcks := make(map[string]map[string]struct{})
for _, result := range successfulHosts {
	...
	hostAcks[result.Host] = ackTopics
}
...
func (t *Broadcaster) checkAcknowledgmentFromAllHosts(hostAcks map[string]map[string]struct{}, topics []string, requireHost RequireAck) bool {
	for _, acknowledgedTopics := range hostAcks {
```

The reference seeds the map with every interested host before it reads the successes, so a host that failed acknowledges nothing:

```ts
const hostAcknowledgments: Record<string, Set<string>> = Object.create(null)
for (const host of Object.keys(interestedHosts)) hostAcknowledgments[host] = new Set()
```

A second, smaller difference: the reference refuses at construction a requirement topic list that names a topic outside the broadcast's topics (`snapshotAcknowledgmentRequirement`, `SHIPBroadcaster.ts:182-193`, `<label> may only reference topics included in this broadcast.`), before anything is sent; go-sdk's `NewBroadcaster` checks the `tm_` prefix alone (`broadcaster.go:64-75`), so such a requirement sends the transaction to every host and then fails.

Steps to reproduce (read from the code at 2ca481c, not run):

1. `NewBroadcaster([]string{"tm_a"}, &BroadcasterConfig{AckFromAll: &AckFrom{RequireAck: RequireAckAll}, ...})` with a resolver naming hosts H1, H2, H3; H1 and H2 answer a STEAK admitting an output for `tm_a`, H3 answers HTTP 500.
2. `Broadcast(tx)` returns `BroadcastSuccess` (`Sent to 2 Overlay Service host(s)`). The reference returns `{ status: 'error', code: 'ERR_REQUIRE_ACK_FROM_ALL_HOSTS_FAILED', description: 'Not all hosts acknowledged the required topics.' }`.

The failure codes and descriptions go-sdk returns (`broadcaster.go:205-244`) are already the reference's three; only the hosts judged differ.

Witness:

- `tests/overlay_ship_requirements_tb.rs` (`a_failed_host_acknowledges_nothing_under_every_requirement_tb_acks`, `a_requirement_naming_a_topic_outside_the_broadcast_refuses_new_tb_acks`) and `tests/vectors/ship_requirements_tb_acks.json` on the open bsv-rs PR #820 (the reference's verdicts recorded under Node 22.18.0)

Pinned reference reading:

- [go-sdk@2ca481c59 overlay/topic/broadcaster.go:162-211](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/overlay/topic/broadcaster.go#L162-L211) (the map from successful hosts, the all-hosts check), [:302-324](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/overlay/topic/broadcaster.go#L302-L324) (`checkAcknowledgmentFromAllHosts`), [:64-75](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/overlay/topic/broadcaster.go#L64-L75) (`NewBroadcaster`)

Sibling reading: [ts-stack@edf6e03da packages/sdk/src/overlay-tools/SHIPBroadcaster.ts:500-512](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/overlay-tools/SHIPBroadcaster.ts#L500-L512) (every interested host seeded), [:564-577](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/overlay-tools/SHIPBroadcaster.ts#L564-L577) (the all-hosts failure), [:182-193](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/overlay-tools/SHIPBroadcaster.ts#L182-L193) (the construction check).

Requested maintainer action: seed `hostAcks` with every interested host (an empty set each) before reading the successful responses, so an all-hosts requirement fails when any interested host did not acknowledge, and check requirement topics against the broadcast's topics in `NewBroadcaster`.

Evidence status: source-read at the pins in this lane; go-sdk was not run; the reference's verdicts are the vector on the open PR. This draft contains no private-key literal.
