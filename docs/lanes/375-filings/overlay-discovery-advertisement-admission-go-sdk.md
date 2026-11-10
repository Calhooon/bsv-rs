keeper's word first

# SLAP and SHIP host discovery admit a host from an advertisement that is unsigned, of any value, or for another transaction

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence rows "The SLAP discovery's admission (#786)" and "The SHIP discovery's admission (#804)" (both: "Theirs: go-sdk, not filed"). Drafted by the filings-1109 lane on 2026-11-09.

A go-sdk `LookupResolver` asks every domain named by any SLAP output its trackers return, and a go-sdk topic `Broadcaster` sends the transaction to every domain named by any SHIP output, whether or not the advertisement carries a valid signature by the identity key it names, whether its output holds 1 satoshi, and whether the BEEF is the transaction the lookup output claims. A tracker or lookup host that returns a forged or stale advertisement (any PushDrop script with the fields `SLAP`/`SHIP`, a key, a domain and a service or topic) steers a Go client's lookups and broadcasts to a domain of its choosing; the TypeScript reference skips that output.

go-sdk reads each advertisement with `admintoken.Decode`, which decodes the PushDrop fields and checks the protocol name alone; nothing verifies the signature field or the locking key's link to the identity key:

```go
script := tx.Outputs[output.OutputIndex].LockingScript
if parsed := admintoken.Decode(script); parsed == nil || parsed.TopicOrService != service || parsed.Protocol != "SLAP" {
	continue
} else if _, ok := hosts[parsed.Domain]; !ok {
	competentHosts = append(competentHosts, parsed.Domain)
```

The reference admits a SLAP host only after four checks (`LookupResolver.ts:2199-2209`):

```ts
if (output.txid !== undefined && output.txid.toLowerCase() !== txid) continue
const selectedOutput = tx.outputs[output.outputIndex]
if (selectedOutput == null || selectedOutput.satoshis !== 1) continue
...
const parsed = await decodeAndVerifyOverlayAdvertisement(script, 'SLAP')
```

and `decodeAndVerifyOverlayAdvertisement` derives the advertisement key from the identity key (invoice `<level>-<protocol>-1`, `PrivateKey(1)` as the counterparty), verifies the signature field over the other fields, and refuses a locking key that is not that derived key (`OverlayAdminTokenTemplate.ts:199-222`). The SHIP reader runs the same checks (`SHIPBroadcaster.ts:771-779`), then admits the domain as its `https` origin (`shipEndpoint(domain, false).origin`) and stops at 32 hosts (`:782`).

Steps to reproduce (read from the code at 2ca481c, not run):

1. A SLAP tracker answers one output whose transaction's output 0 is a 1000-satoshi PushDrop script with the fields `SLAP`, any 33-byte key, `https://attacker.example`, `ls_example` and any bytes as the signature. `FindCompetentHosts(ctx, "ls_example")` returns `["https://attacker.example"]`, and `Query` sends the lookup there. The reference's `extractHostsFromAnswer` returns no host (the value check at `:2203` and the signature check at `:2206` each skip it).
2. The same output with the fields `SHIP` and `tm_example`: `Broadcaster.FindInterestedHosts` returns `["https://attacker.example"]` and the transaction is sent there; the reference's `#fetchInterestedHosts` admits none.
3. A genuine advertisement signed by the operator but carried at 0 or 2 satoshis, or under a lookup output whose `txid` names another transaction: admitted by go-sdk, skipped by the reference.

bsv-rs admits a host as the reference does at both sites since #786 and #804, its advertisement read through the reference's `decodeAndVerifyOverlayAdvertisement` since #544; the recorded vectors carry the reference's admissions for each case.

Witness:

- [tests/lookup_slap_admission_786.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/lookup_slap_admission_786.rs) (`a_slap_advertisement_of_zero_satoshis_admits_no_host_786`, `a_slap_advertisement_of_two_satoshis_admits_no_host_786`, `a_slap_advertisement_whose_txid_hint_disagrees_admits_no_host_786`, `the_reference_recorded_admissions_are_this_crates_786`) and [tests/vectors/lookup_slap_admission_786.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/lookup_slap_admission_786.json) (cases `zero_satoshis`, `two_satoshis`, `hint_disagreeing`)
- [tests/overlay_ship_discovery_804.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/overlay_ship_discovery_804.rs) and [tests/vectors/ship_discovery_admission_804.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/ship_discovery_admission_804.json) (cases `zero_satoshis`, `two_satoshis`, `hint_disagreeing`, `https_bsvauth`, `wss`, `hosts_33`)
- [tests/overlay_admin_token_envelope_544.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/overlay_admin_token_envelope_544.rs) (`the_slap_discovery_reads_only_an_authenticated_advertisement_544`, `the_ship_discovery_reads_only_an_authenticated_advertisement_544`)

Pinned reference reading:

- [go-sdk@2ca481c59 overlay/lookup/resolver.go:184-208](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/overlay/lookup/resolver.go#L184-L208) (SLAP), [overlay/topic/broadcaster.go:278-299](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/overlay/topic/broadcaster.go#L278-L299) (SHIP), [overlay/admin-token/admin-token.go:41-71](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/overlay/admin-token/admin-token.go#L41-L71) (`Decode`, no signature check)

Sibling reading:

- [ts-stack@edf6e03da packages/sdk/src/overlay-tools/LookupResolver.ts:2194-2216](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/overlay-tools/LookupResolver.ts#L2194-L2216) (`extractHostsFromAnswer`)
- [ts-stack@edf6e03da packages/sdk/src/overlay-tools/SHIPBroadcaster.ts:725-789](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/overlay-tools/SHIPBroadcaster.ts#L725-L789) (`#fetchInterestedHosts`)
- [ts-stack@edf6e03da packages/sdk/src/overlay-tools/OverlayAdminTokenTemplate.ts:198-222](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/overlay-tools/OverlayAdminTokenTemplate.ts#L198-L222) (`decodeAndVerifyOverlayAdvertisement`)

Not asked here: the reference's resource bounds at the SHIP site (256 outputs, 16 MiB per BEEF, 64 MiB in total), which are its own safeguards rather than a protocol rule; and the unchecked output index at `broadcaster.go:283`, a crash filed separately (the draft `ship-discovery-output-index-panic-go-sdk`).

Requested maintainer action: admit a SLAP or SHIP host only from an output of exactly 1 satoshi, whose lookup `txid` (when one is given) is the BEEF's transaction, and whose advertisement verifies against its identity key as the reference's `decodeAndVerifyOverlayAdvertisement` does.

Evidence status: source-read at the pins in this lane; neither go-sdk nor the reference was run for this draft. The linked Rust tests and the vectors (recorded from the reference by the #786 and #804 recorders under Node 22.18.0) are the reproducible witness. This draft contains no private-key literal.
