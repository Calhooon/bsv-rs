# Lane fix-tb-acks: the topic broadcaster's acknowledgment requirements

The overlay bucket's blocking lines 3, 4 and 5 of 2026-11-09 (the reads of
PR #813). Started from `c96f3c7e` (`origin/beta`'s tip at the lane's start).

## The three sites, side by side

The reference, `ts-stack@edf6e03`
`packages/sdk/src/overlay-tools/SHIPBroadcaster.ts`:

```
182-193: snapshotAcknowledgmentRequirement(value, topics, label):
         'all' | 'any' returned; a list read by canonicalTopics(value, label, true)
         (<= 64 unique /^(?=.{1,50}$)tm_[a-z]+(?:_[a-z]+)*$/ names, :156-180);
         a topic outside `topics` -> TypeError(`${label} may only reference
         topics included in this broadcast.`)
430-444: called for 'All-host acknowledgment requirement' (default []),
         'Any-host acknowledgment requirement' (default 'all'),
         then per specific host after its key (:212-216,
         `Acknowledgment requirement for ${canonicalHost}`)
511-512: hostAcknowledgments seeded: every interested host -> new Set()
538-546: allHosts, then anyHost, then specificHosts; the earliest failure returned
    572: ERR_REQUIRE_ACK_FROM_ALL_HOSTS_FAILED 'Not all hosts acknowledged the required topics.'
    584: any-host list -> { requiredTopics: r, require: 'all' }
    596: ERR_REQUIRE_ACK_FROM_ANY_HOST_FAILED 'No host acknowledged the required topics.'
    615: ERR_REQUIRE_ACK_FROM_SPECIFIC_HOSTS_FAILED 'Specific hosts did not acknowledge the required topics.'
```

The base, `c96f3c7e` `src/overlay/topic_broadcaster.rs`:

```
114-137: new: topics non-empty and tm_-prefixed; the specific-host keys (#804);
         no requirement's topic list read
241,258: host_acks.insert only for a host whose steak was non-empty
290-297: any check failing -> ERR_REQUIRE_ACK_FAILED, the check's own words
         behind `overlay error: `
352-360: the all-hosts check over host_acks (successful hosts alone)
any-host: Some(list) read as one topic of the list at one host; an empty
         list a failure
```

The tip:

```
src/overlay/topic_broadcaster/requirements.rs
  snapshot(requirement, topics, label): the reference's :182-193, its words
  seeded(interested, successful): :511-512
  AckFailure { AllHosts, AnyHost, SpecificHosts }: code() and description(),
         :572, :596, :615
  check_acknowledgments: the three checks in :538-546's order; an any-host
         list `require: 'all'` (:584); an empty list no check
src/overlay/topic_broadcaster.rs
  new: snapshot for the all-host, then the any-host requirement; the
       specific hosts through discovery::specific_hosts with a check per
       origin (:212-216)
  broadcast_tx: requirements::seeded(interested_hosts.keys(), host_acks),
       then the failure's code and description
```

`RequireAck::All` and `Any` carry no list and are not checked, as the
reference returns `'all'` and `'any'` as given; `RequireAck::None` has no
reference form and reads as the reference's empty list (no check at
construction; no check at broadcast for all hosts and any host; for a
specific host the presence check alone, as the reference's `continue`).

## The recording

`tests/support/ship_requirements_tb_acks.mjs`, the reference's own
`TopicBroadcaster` from a bundle of `git archive edf6e03 packages/sdk`
(`bun build mod.ts --target node --format esm`), under Node v22.18.0, a stub
resolver answering four SHIP advertisements (two hosts, two topics, the
reference's `OverlayAdminTokenTemplate` under `ProtoWallet(PrivateKey(7))`) and
a scripted facilitator; nothing dialled. 20 constructions (11 refused) and 120
broadcasts (8 host behaviours by 15 requirements: 53 successes, 20
all-hosts, 9 any-host, 23 specific-hosts, 15 all-hosts-rejected). Two runs
byte-identical (`cmp`).

## RED

A scratch copy of `c96f3c7e` (`git archive`) under `~/bsv/targets`, the test
file and vector overlaid, its own target dir:

```
a_requirement_naming_a_topic_outside_the_broadcast_refuses_new_tb_acks: all_hosts_outside
  left: Ok(())
 right: Err("overlay error: All-host acknowledgment requirement may only reference topics included in this broadcast.")
nothing_is_sent_under_a_requirement_the_reference_refuses_tb_acks: {"all":["tm_other"]}
  left: ["https://a.ship-requirements-tb-acks.invalid", "https://b.ship-requirements-tb-acks.invalid"]
 right: []
a_failed_host_acknowledges_nothing_under_every_requirement_tb_acks: "ack_fail__all_hosts_all"
  left: "success"
 right: "error"
an_any_host_topic_list_asks_one_host_for_every_topic_tb_acks
  left: ("success", None, None, Some("Sent to 2 Overlay Services hosts."))
 right: ("error", Some("ERR_REQUIRE_ACK_FROM_ANY_HOST_FAILED"), Some("No host acknowledged the required topics."), None)
the_failed_requirement_carries_the_references_code_and_description_tb_acks: idle_idle__all_hosts_all
  left: ("error", Some("ERR_REQUIRE_ACK_FAILED"), Some("overlay error: Not all hosts acknowledged the required topics."), None)
 right: ("error", Some("ERR_REQUIRE_ACK_FROM_ALL_HOSTS_FAILED"), Some("Not all hosts acknowledged the required topics."), None)
```

A census on the base over the 120 broadcasts: 27 verdicts differ, 7 false
successes (an all-hosts requirement with a failed or topicless host, 6; an
any-host list split across two hosts, 1) and 20 false failures (an empty
any-host list, and a failed specific host under an empty list), and 45 more
in code or words (`/Volumes/Lanes/out/bsv-rs/fix-tb-acks/base-census.log`).
All five green on the tip.

## The old code

`ERR_REQUIRE_ACK_FAILED` in this crate: `src/overlay/topic_broadcaster.rs`
(the one emission, replaced), `src/overlay/CLAUDE.md` (the code table),
`tests/overlay_ship_discovery_804.rs:359,471` (now the recorded
`ERR_REQUIRE_ACK_FROM_SPECIFIC_HOSTS_FAILED`, the specific-host verdicts now
compared by code), `CLAUDE.md`'s #804 row (the residue, closed),
`docs/lanes/fix-804.md:60` (history, kept). No conformance classifier names
it. The dependents read by path: `~/bsv/bsv-overlay-cloudflare` names
`TopicBroadcaster::broadcast_tx` in one doc comment
(`crates/overlay-cloudflare/src/mainnet_fanout.rs:19`), no code;
`~/bsv/bsv-wallet-toolbox-rs` and `~/bsv/bsv-wallet-cli` name neither.

## The gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D
warnings`; `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features`;
`overlay_ship_requirements_tb` three times (one `--test-threads=1`), 5 passed
each; `--lib overlay` 96 passed; the ten files (`fixtures_replay`, the nine
`overlay_*`) 173 passed; `--test 'arch_*'` 97 passed; examples built;
`readme_examples` 1 passed; the wasm32 slice built; `tools/ratchet/run
--check --against c96f3c7e` passes; `mutants_entries.py` PASS;
`rows_from_sources.py --check` 0 refusals; gitleaks over `c96f3c7e..HEAD`.
