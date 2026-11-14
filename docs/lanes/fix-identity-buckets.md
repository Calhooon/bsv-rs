# Lane fix-identity-buckets: the three identity buckets (#818, #907, #959), every line answered

Opened from `origin/beta` at `2b419d90` (2026-11-14), rebased before the
gate onto `cb950611` (#912; twelve commits had landed, one `CHANGELOG.md`
conflict, both sides kept). One pull request. No
public item moves, no wire byte, verdict or error text; the only files under
`src/` that change are test modules (`#[cfg(test)]`) and the module manual.
The reference is `ts-stack@edf6e03`, bundled with bun and run under Node
v22.18.0 by each recorder's own recipe (its header).

## The table

Fates: BUILT (a test RED before it, or a record corrected), ALREADY TRUE (a
later pull request did it: where), NEEDS A DECISION (nothing built: the
question below), NOT A DEFECT.

| Line | What | Fate | The evidence |
|---|---|---|---|
| #818.1 | an attribute-filter drop is counted nowhere | needs a decision (D1) | still so: `src/identity/client.rs:717` drops, nothing counts |
| #818.2 | the other identity doors send questions the overlay refuses | already true | #905 (lane fix-818b): `src/identity/client_door_args.rs`, called at `client.rs:677`, `:767`, `:800`; `tests/identity_door_args_818b.rs` (7 tests, 46 recorded cells) |
| #818.3 | four mutations of the #751/#756 code survive | already true | PR #897: `src/identity/client_attributes_818_tests.rs` (ten cases by name), `tests/identity_query_bounds_756.rs` `a_key_tagged_03_is_admitted_818`; this lane's run finds none of the four alive (below) |
| #818.4 | the evidence count over repeated entries is unpinned | already true | PR #897: `src/identity/evidence_818_tests.rs` `a_repeated_entry_counts_toward_the_transactions_bound_818`; widened here by #907.5b and #907.6 |
| #818.5 | a displaced liar's count is not in the CHANGELOG | already true | PR #897: `CHANGELOG.md`, "A displaced liar's count." under the #818 entry; the two counters' rustdoc (`src/identity/evidence.rs:86-108`) |
| #907.1 | `add_contact` and `remove_contact` answer `Ok` when the wallet failed | already true | #904: `src/identity/contacts.rs:193-217` (every `?`, the cache written last), `contacts_actions.rs:307-336`; `tests/contacts_wallet_failures.rs` (29 tests) |
| #907.2 | the contact actions' words, labels and options | already true | #904: `src/identity/contacts_actions.rs:230`, `:242`, `:272-273`, `:350-351`, `:505`; `tests/contacts_listed_spend.rs` against the recorded createAction arguments; the root list's #904 row |
| #907.3 | `IdentityClient::new` leaves no door to its resolver's hint count | needs a decision (D2) | still so: `client.rs:305-311`; a public accessor |
| #907.4a | one `cargo mutants` run over the matcher, the bounds and the evidence check | built | the run below; three recorded cases for its three live survivors |
| #907.4b | whether `src/identity/` becomes a mutation surface | needs a decision (D3) | `.github/scripts/nightly_mutants.py:28-34`; #602's rule |
| #907.5 | two blind spots in #897's tests | built | (a) the order asked asserted; (b) the vector read whole and `admit` run |
| #907.6 | inputs no identity test serves | built | 22 recorded cases and shapes, 4 door tests; each value the recorder's |
| #959.1 | the stable line answers a cached list in a `HashMap`'s order | needs a decision (D4) | not this lane's line (beta): a stable patch or the cut |
| #959.2 | a key the basket holds twice | needs a decision (D5) | a new public door; nothing built |
| #959.3 | what the contacts replay compares | built | the recorder's second pass and five directed sequences; the replay |
| #959.4 | three lines of the contacts manager no test holds | built | the two requests recorded and compared; the tag helper's test; the tool at 0 missed outside the three equivalents |

Counts: built 5, already true 6, needs a decision 5, not a defect 0. Two
more differences were found by #959.3's replay and are stated, each with a
question (D6, D7).

## #959.3 and #959.4: the replay

`tests/support/contacts_replay_reference.mjs` (a mode of the #326 recorder),
`tests/support/contacts_replay_wallet.rs`, `tests/contacts_replay.rs`,
`tests/vectors/contacts_replay.json`.

Before any edit the recorder reproduced the committed corpus byte for byte.

**The recorder.**

- A second generated pass, `drawStep959`, from a stream of its own (the seed
  `bsv-rs#959`): 200 sequences of 4 to 16 steps, 2,028 steps (1,017 with no
  fault, 486 with one, 525 with two). The seventh fold's 320 are drawn as
  they were: with the new columns taken out, its sequences and its 13
  directed ones equal the committed ones (checked by a script, not by eye).
- Four contacts (the scalar 6 beside 3, 4 and 5); a save names a contact not
  held two times in three. 19 answers of four contacts in the pass, more in
  the directed sequences.
- Every member `validateContact` keeps (`ContactsManager.ts:171-198`) is
  drawn for a save and an update and recorded on every answer: the avatar,
  the abbreviated key, the three badge members, the metadata. Each drawn
  value is one the validator returns as given.
- A save, an update and a read by key are drawn over a cold cache too
  (`cold: true`: 162 saves, 25 updates, 35 reads by key). The reference loads
  the whole basket there (`:529-531`, `:331-338`); what the load cached is
  read back from the reference itself, which asks the wallet nothing for it,
  and the recorder throws if its model disagrees.
- createHmac's protocol, key ID, counterparty and data and encrypt's protocol
  and counterparty are recorded where the wallet received them (2,682 and
  1,917 requests, every one `self` under `[2, 'contact']`).
- A sequence that leaves the basket holding one key in two outputs is not
  kept (D5's cell); none was drawn (`discarded_959: 0`).
- Five directed sequences: `cold_save_959`, `cold_save_listing_faults_959`,
  `cold_read_by_key_959`, `members_replaced_by_an_update_959`,
  `four_contacts_959`.
- Two runs byte-identical (`cmp`); 520 sequences and 18 directed.

**The replay.**

- A contact is compared as the reference's record, member for member
  (`contact_answer`: `notes` and `tags` inside `metadata`, an absent avatar
  the empty text, as `contacts_record.rs` writes them).
- A cold step is made as a caller of this crate composes it: a plain read,
  then the call (`load_as_the_reference_does`). `add_contact` and
  `get_contact` read the cache alone, the root list's stated residue; the
  replay does not hide it, it names it, and D6 is the question. A cold
  update whose load did not cache its contact goes through `add_contact`
  (`update_contact`'s `ContactNotFound` has no reference twin).
- The arguments compared include the two key requests.
- `get_contacts_by_tag_matches_the_whole_tag_whatever_its_case_959`: the tag
  helper has no reference twin, so a test of its own (four contacts tagged
  `Work`, `work` beside another tag, `WORK`, `homework`).
- Green: 538 of 538, three runs, one with `--test-threads=1`; about 13 s.

**RED.** A scratch copy of the tip (`git ls-files` into the lane's out
folder, target `/Volumes/Lanes/targets/fix-identity-buckets-scratch`, both
removed), each plant behind a switch read from the environment so that one
build served them all, one live a run, against the replay binary alone
(`plant-<name>.log`):

| Plant | Where | RED |
|---|---|---|
| the tag HMAC's `counterparty` deleted | `contacts.rs:283` | 527 of 538 sequences, `the arguments: ... "counterparty": Null` |
| the encryption's `counterparty` deleted | `contacts_actions.rs:75` | 493 of 538 |
| the tag match case-sensitive | `contacts_cache.rs:166` | the tag test, `left: ["Carol"]`, `right: ["Bob", "Carol", "Dave"]` |
| the tag match by a part of a tag | the same | the tag test, `left: [.., "Erin"]` |
| an update keeps the cached badge label | `ContactsCache::save` | 35 of 538, the earliest sequence 326, step 6 |
| a load drops the metadata | `contacts_record.rs`, `contact_of` | 61 of 538 |
| a load empties the click URL | the same | 86 of 538 |
| the replay's cold load skipped | `tests/contacts_replay.rs` (the test's own line) | 155 of 538, `this crate [], the reference ["listOutputs"]` |
| a removal by `swap_remove` | `ContactsCache::remove` | 3 sequences (1 on the corpus before, the eighth fold's O4) |
| removing the head reverses the rest | the same | 3 sequences |
| an update moved to the front | `ContactsCache::save` | 27 sequences (11 before, O3) |

The cold plant is in the test, not in the crate: this crate's cold save
makes no load to skip. It shows the comparison is live, and it is what
porting the load would delete.

**The tool.** `cargo mutants` 27.1.0, `--in-place` on the scratch copy,
`--features full,http --baseline skip`, round-robin shards each under ten
minutes, against `--lib` and `contacts_replay`, `contacts_wallet_failures`,
`contacts_listed_spend`, `contacts_signaction_326`, `identity_tests`,
`identity_door_args_818b`, `identity_wallet_calls_318`:

| File | Made | Caught | Unviable | Missed |
|---|---:|---:|---:|---|
| `contacts.rs` | 28 | 24 | 4 | 0 (`283:21`, the `counterparty` deletion, caught) |
| `contacts_cache.rs` | 29 | 20 | 6 | 3: `87:56` `+` as `*`, `87:24` `>` as `>=` and as `==`, the three stated equivalents |

`contacts_actions.rs` was not swept again (55 mutants, the third fold's
table); its `75:21` is the plant above.

**What the replay shows about the tip (stated, not mended; D7).** A read
answered from the cache after a save answers the contact as the caller gave
it (`contacts.rs:217`, `cache.save(contact)`); the reference caches the
record `validateContact` returned (`:527-534`). Run on both sides with a
`badgeClickURL` of `https://example.com` and a `metadata` of `{}`: this crate
warm `"https://example.com"`, `Some({})`, after a forced refresh
`"https://example.com/"`, `None`; the reference `https://example.com/` and
`{}` both times. The generator draws no such value, so the corpus is green.

## The fold: the two stated differences held by tests as they stand (2026-11-14)

The three reads' one item (pull request #991): D6 and D7 were stated and no
test held them, so a mend or a regression left the rows stale with every
test green. Tests and records alone; no code under `src/` moves. Both
differences are ruled (the captain) to be conformed to the reference before
the cut by a later lane, which turns each test over; each assertion names the
reference's answer beside the one it holds today. Rebased onto beta
`5ad961d7` (after `e0326bd5`, beta moving during the run; one changelog conflict each time, both sides kept).

**D7, three cells** (`a_save_answers_the_callers_form_until_a_refresh_stated_959`,
`tests/contacts_replay.rs`). The recorder adds `STATED_959`, written as
`stated_959` beside the sequences and recorded after them: per cell a forced
read, one save, a warm plain read, a warm read by key, a forced read, a
plain read. The reference's recorded answers (`ts-stack@edf6e03`, Node
v22.18.0; `ContactsManager.ts:527-534`, `:566`, `:104-122` read at the pin):

| cell | the reference, all four reads | this crate, warm | this crate, after the refresh |
|---|---|---|---|
| `badgeClickURL` `https://example.com` | `https://example.com/` | `https://example.com` | `https://example.com/` |
| `metadata` `{}` | `{}` | `Some({})` | `None` |
| tags and notes inside `metadata` | `metadata` `{tags: [work], notes: ..}` | `tags` empty, `notes` none, `metadata` as given; `get_contacts_by_tag` and `search_contacts` miss the contact | `tags` `[work]`, `notes` set, `metadata` none; both helpers find it |

The third cell is the strength read's: the record equals the reference's at
all four reads (the replay's comparator folds `notes` and `tags` back into
`metadata`, which hid it); the difference is in this crate's own fields and
its two helpers. The vector: the recorder before the change reproduced the
committed file byte for byte; after it, two runs identical (SHA-256
`b00ee1cc...e960b71a`) and the diff against the committed file one added
line (`stated_959`), every sequence and directed line as it was.

RED, on a scratch copy of the tip (target
`/Volumes/Lanes/targets/fix-identity-buckets-fold-red`, both removed after)
with `add_contact` caching `record::contact_of(record, added_at)`: the test
fails at the click URL (`left: "https://example.com/"`, `right:
"https://example.com"`); with that cell's two warm assertions out, at the
empty metadata (`left: None`, `right: Some(Object {})`); with those out, at
the tag read (`get_contacts_by_tag` not empty). The other three tests of the
file pass under the plant: the mend was silent until this test.

**D6, three cells** (`tests/contacts_wallet_failures.rs`, beside the cold
`saveContact` assertion of the signable-fault test), each beside the
reference's recorded step in `tests/vectors/contacts_replay.json`:

| test | this crate today | the reference, recorded |
|---|---|---|
| `a_cold_add_makes_no_listing_of_the_basket_stated_959` | one listing, the tagged one, after the HMAC; the call list the reference's less its leading call | `cold_save_959` step 0: `listOutputs` (`locking scripts`, no tag) leading, two listings |
| `a_cold_get_contact_answers_none_for_a_key_the_basket_holds_stated_959` | `None`, no wallet call | `cold_read_by_key_959` step 4: `listOutputs` leading, the contact answered |
| `a_cold_update_refuses_contact_not_found_for_a_key_the_basket_holds_stated_959` | `ContactNotFound(key)`, no wallet call | `cold_save_959` step 6: `listOutputs` leading, `ok`, signAction asked |

RED, 3 of 3, on the same scratch copy with `add_contact`, `get_contact` and
`update_contact` each opening with a plain read when the cache is not
loaded (`left: "list_outputs"`, `right: "create_hmac"`; the `is_none`
assertion; `left: IdentityError("Unable to authenticate a contact lookup
result")`, `right: ContactNotFound(..)`, the double's listing carrying no
BEEF to spend from).

The clause: the root `CLAUDE.md`'s #904 row names the three D7 cells, the
three D6 cells and the four tests; `CHANGELOG.md`'s entry and parity note
the same; `tests/CLAUDE.md` counts 32 and 4.

**The bound, as it stands.** These tests and the replay hold what the cache
answers and keeps with up to four contacts, every member of the record, and
up to two faults a step. They do not hold: a step with three or more faults;
a cache of five or more; the load's concurrent reads, compared by count; a
member value the validator rewrites; `search_contacts`; a key the basket
holds twice (D5).

## #907.5 and #907.6: the tests and the recorded cases

Each recorder reproduced its committed vector byte for byte before it was
edited; each new recording was run twice, byte-identical; each vector's diff
is additions alone.

| Vector | Added | The reference's answers |
|---|---|---|
| `identity_attributes_751.json` (52 to 63) | `fuzzy_thrice_repeated_token` | `a a a` keeps `[1, 2, 4]` of `a a`, `a a a`, `aaa`, `aa`, `a b a x a` |
| | `fuzzy_vertical_tab_form_feed_and_next_line` | `[0, 1, 2]`: no line ends there |
| | `fuzzy_carriage_return_line_feed` | `[1, 2]`: `alice\r\nsmith` and `alice\n\rsmith` not kept |
| | `any_index_name_zero`, `_minus_zero`, `_decimal_point`, `_two_to_the_32`, `any_empty_name` | `[1]`, then `[0, 1]` four times: `0` alone is an array index |
| | `any_phrase_is_the_whole_quoted_text`, `any_two_phrases`, `any_negated_phrase_right_after_a_phrase` (the run's survivors) | `[1]`, `[0, 2]`, `[0, 3]` |
| `identity_query_bounds_756.json` (70 to 79) | `key_prefix_03_upper_case`, `_p_plus_1`, `_no_point`, and the certifier's three | reached, reached, refused (`must be a valid compressed public key`) |
| | `two_faults_name_then_value_u32_max`, `_leading_zero`, `_plus_sign` | the name fault named each time |
| `identity_evidence_818.json` (2 to 4 shapes) | `raw_repeat_at_bound`, `raw_repeat_over_bound` | read; `limit` at `TransactionEvidence.ts:117`, 257 transactions |

Every answer is what the tip gives: no finding. The hint cases are this
crate's counters (the reference counts neither): the liar asked ahead of the
honest host in every displacement case, `(resolver, identity)` `(1, 0)` for a
hintless and an upper-case honest copy displacing and for the honest host
ahead, `(2, 1)` for two liars, `(1, 0)` and one result under each of the
four other doors.

RED, the same scratch copy and switch (`plant2-<name>-*.log`):

| Plant | RED |
|---|---|
| the rank's tie-break reversed (`host_reputation_tracker.rs:397`) | the three #907 hint tests, `asked: ["asked-honest", "asked-liar"]`; the #818 test green, which is the blind spot |
| raw entries counted once at the transactions bound (`evidence.rs:226`) | the two #907 evidence tests; the #818 test green |
| the matcher's tokens cut to two | `a_token_three_times_needs_three_occurrences_907` |
| VT, FF and U+0085 made line ends | `a_vertical_tab_a_form_feed_and_a_next_line_end_no_line_907` |
| `0` made no array index (`js_order`) | `zero_is_an_array_index_and_four_names_like_one_are_not_907` |
| the point check skipped for an `03` key (`query_bounds.rs`) | `an_03_key_in_upper_case_or_past_p_is_sent_and_one_of_no_point_refused_907` |

Agreement pins, green on the tip with no plant found that only they catch:
the CR LF case, the four names that are no index, the three names of the
question's walk, `admit`'s two outcomes on the #818 shapes (a plant there is
already caught by #730's test).

## #907.4a: the run

`cargo mutants` 27.1.0 as above, against `--lib` and the door tests named:

| File | Tests beside `--lib` | Made | Caught | Unviable | Timeout | Missed |
|---|---|---:|---:|---:|---:|---|
| `client_attributes.rs` | `identity_query_attributes_751`, `identity_query_bounds_756`, `identity_door_args_818b`; `identity_query_filters_746` for `53:69` | 107 | 99 | 1 | 4 | 3 |
| `query_bounds.rs` | the same four | 22 | 21 | 1 | 0 | 0 |
| `evidence.rs` | `identity_evidence_730`, `_736`, `identity_evidence_hint_735`, `identity_hint_displaced_818`, `identity_resolve_737` | 48 | 45 | 3 | 0 | 0 |

- Before this lane's cases the run left eight alive in `client_attributes.rs`
  on its selection. `53:69` is caught by `identity_query_filters_746` (not in
  the selection). Four were live survivors of `query_parts`, the phrase
  scanner: `234:32` and `234:36` `+` as `*` (a phrase cut by one unit),
  `236:26` `+` as `*` and as `-` (the scan resumed on the closing quote).
  Three recorded cases catch them, each on the tool's re-run.
- The three left are equivalent. `112:18` `==` as `!=` in `lines` moves only
  where an empty line stands, and an empty line matches nothing a line with
  text does not. `137:24` `<` as `<=` in `canonical` differs at U+0080 alone,
  which upper-cases to itself. `256:54` `>` as `>=` in `part_match` makes a
  lone `-` negative, whose term is then empty and neutral either way
  (`any_dash_alone`).
- The four timeouts are `query_parts`' loop counters (`243:16`, `244:16`
  twice, `247:16`): the scan never ends. Counted as timeouts, not as caught.
- None of #818.3's four mutations is alive.

## The questions

**D1 (#818.1). Should a certificate the attribute filter drops be counted?**
Ways: an additive `IdentityClient::attribute_filter_drops() -> u64`, as #735
counts hint contradictions; or nothing. Cost to a caller: none either way
(additive); without it an answer padded with non-matching certificates reads
as an empty list with no signal. The reference counts nothing, and an honest
overlay returns non-matching certificates (stem matches, other types), so the
count must not charge a host. Recommendation: the accessor, after the cut.

**D2 (#907.3). How does a caller of `IdentityClient::new` read its resolver's
hint count?** Ways: `IdentityClient::lookup_txid_hint_contradictions() -> u64`
(one number, no new type in a signature); or `resolver() -> &Arc<LookupResolver>`
(wider: every resolver door); or the documented `with_resolver`. Cost: none
(additive). Recommendation: the one-number accessor, with D1.

**D3 (#907.4b). Does `src/identity/` become a mutation surface?** #602's
rule: a surface's floor is the measured value, never lowered. Measured here on
five files: 234 mutants, 209 caught, 15 unviable, 4 timeouts, 6 missed, all
six equivalent. Ways: add `"identity": ["src/identity/**/*.rs"]` to
`SURFACES` with the six listed in `.cargo/mutants.toml`; or the five files
alone; or nothing. Cost: nightly minutes (about 40 s a mutant here; the
module has 20 more source files unmeasured, `client.rs` the largest).
Recommendation: the five measured files as the surface now, the rest when
measured.

**D4 (#959.1). A stable patch or the cut?** `main` carries the `HashMap`
order with the whole of what #904 mended. Ways: the 0.9.0 cut answers it (one
sentence in the migration notes: 0.8.x answers a cached list in no fixed
order); or a stable patch of the cache alone. Cost of the patch: a seventh
class of pick the direction rule does not name. Recommendation: the cut.

**D5 (#959.2). A door for every entry of a key?** The reference: a load keeps
every decrypted output (`ContactsManager.ts:376`), a read by key filters the
cache (`:388-390`, `cachedContacts.filter(c => c.identityKey === identityKey)`),
and the identity client's by-key door returns what it read
(`IdentityClient.ts:575-576`). The door:

```rust
impl<W: WalletInterface> ContactsManager<W> {
    /// Every cached contact of the key, in the cache's order.
    pub async fn get_contacts_for_key(&self, identity_key: &str) -> Result<Vec<Contact>>;
}
impl<W: WalletInterface> IdentityClient<W> {
    pub async fn get_contacts_for_key(&self, identity_key: &str) -> Result<Vec<Contact>>;
}
```

with `resolve_by_identity_key` with contacts answering one identity an entry;
`get_contact` kept. Cost: additive, but the by-key door's answer grows from
one identity to several for a basket holding a key twice (a state only the
wallet's own writes reach). The recorder already detects the state
(`heldTwice`) and discards such a sequence; with the door it keeps them and
the replay compares the list. Recommendation: the door, after the cut.

**D6 (found by #959.3). Should a save and a read by key load the basket over
a cold cache, as the reference does (`:529-531`, `:331-338`)?** Today
`add_contact` and `get_contact` read the cache alone (the root list's stated
residue; #558's too). Ways: port the load (`add_contact` and `get_contact`
call the plain read when the cache is not loaded); or keep the residue. Cost
of the port: a cold save asks the wallet one more listing and its reads, and
fails when that listing fails; a cold `get_contact` asks the wallet where it
answered `None`. The corpus already holds the reference's answers for 222
cold steps: the port is tested by deleting `load_as_the_reference_does` from
the replay. Recommendation: port it before the cut, with D7.

**D7 (found by #959.3). Should the cache hold the validated record after a
save?** Ways: `cache.save(record::contact_of(record, contact.added_at))` in
`add_contact`, and `contact_of` keeping an empty `metadata`; or the stated
difference. Cost: a read after a save answers the record's form (the URL as
serialized, an absent avatar `None`, the abbreviated key present, `notes` and
`tags` in their own members) where it answered the caller's own value; it
then equals what the same read answers after a refresh. Recommendation: mend;
the generator then draws rewritten values too.

## The gate (2026-11-14, on `cb950611`)

Target dir `/Volumes/Lanes/targets/fix-identity-buckets`, removed after, with
the scratch copy, its target and the ratchet's.

- The three `cargo fmt` lines of `ci.yml`'s Rustfmt step: clean.
- `cargo +1.100.0 clippy --all-targets --all-features -- -D warnings`: clean.
- `cargo check --all-targets --all-features`: built.
- `--lib identity`: 120 passed, three runs, the third with `--test-threads=1`.
- The four touched files (`contacts_replay`, `contacts_wallet_failures`,
  `identity_hint_displaced_818`, `identity_query_bounds_756`): 49 passed,
  three runs, the third with `--test-threads=1`.
- Every `tests/identity_*.rs` and `tests/contacts_*.rs` with
  `fixtures_replay`, `readme_examples` and
  `auth_identity_certificate_field_order_394`: 47 binaries, 291 passed, 0
  failed, 4 ignored.
- `--test 'arch_*'`: 36 binaries, 188 passed, 0 failed, 1 ignored.
- `--lib` whole: 1,846 passed, 4 ignored; the two BEEF census files
  (`beef_v1_txid_only_writer_817`, `beef_writer_refusals_817`): 22 passed,
  their figures unmoved (no vector of the lane holds a BEEF's bytes).
- `RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --all-features`: clean.
- The wasm32 slice of rule 6: built.
- `tools/ratchet/run --check --against origin/beta`: all 7 counters pass.
- `mutants_entries.py`: PASS, 28 entries. `rows_from_sources.py --check`: 0
  refusals; its 10 unit tests pass.
- `gitleaks git` over `origin/beta..HEAD`: no leaks.

Not run: the conformance corpus (no interpreter or BEEF code moved), the
whole integration suite beyond the files named, semver-checks (no public
item moves; the only `src/` changes are `#[cfg(test)]` modules and a manual).
