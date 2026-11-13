# Identity Module
> Certificate-based identity resolution and contact management for the BSV ecosystem

## Overview

The identity module provides certificate-based identity discovery and management for BSV applications. It enables users to:

- **Resolve identities** by public key or attribute values (email, phone, etc.)
- **Discover certificates** associated with an identity
- **Parse certificates** into user-friendly display formats
- **Manage contacts** with encrypted local storage
- **Reveal attributes** publicly on the overlay network
- **Revoke revelations** by spending identity tokens

This module integrates with the `auth` module for certificate handling and the `overlay` module for network communication.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root with re-exports (112 lines) |
| `types.rs` | Core types: KnownCertificateType, DisplayableIdentity, Contact, configs (779 lines; its unit tests in `types_tests.rs` since #552); `Contact` `#[non_exhaustive]` with `new` and `with_` setters, no `Default`, since #552's fold; `Contact::badge_icon_url`, `badge_label`, `badge_click_url` since #552 (the reference record's `badgeIconURL`, `badgeLabel`, `badgeClickURL`, `""` where unset; `from_identity` copies an identity's badges and `to_displayable_identity` answers the stored ones (`""` where unset) since #558, the reference's contact being its identity (`ContactsManager.ts:28`; pinned by `tests/identity_contact_badges_558.rs` against `tests/vectors/identity_contact_badges_558.json`, recorded by `tests/support/identity_contact_badges_558.mjs`); pinned by `tests/identity_contact_badges_552.rs` against `tests/vectors/contact_badges_552.json`, recorded by `tests/support/contact_badges_552.mjs`); `Contact::abbreviated_key: Option<String>` and `with_abbreviated_key` since #559 (the record's stored `abbreviatedKey`, `Some` for a contact read from a token and written back as held, as the reference's `saveContact` writes the caller's value, `ContactsManager.ts:185,527-528,748`; `None` for a contact built here, written as `to_displayable_identity`'s form; pinned by `tests/identity_contact_abbreviated_key_559.rs` against `tests/vectors/contact_abbreviated_key_559.json`, recorded by `tests/support/contact_abbreviated_key_559.mjs`; `from_identity` copies an identity's `abbreviated_key` as `Some` and `to_displayable_identity` answers the stored one, the computed form only for `None`, since #568, the reference's contact being its identity (`ContactsManager.ts:28`; pinned by `tests/identity_from_identity_abbreviated_key_568.rs` against `tests/vectors/from_identity_abbreviated_key_568.json`, recorded by `tests/support/from_identity_abbreviated_key_568.mjs`)); `ContactsManagerConfig::protocol_id` `(2, "contact")`, the reference's `[2, 'contact']` (`ContactsManager.ts:30`), read by every contact site since #542 (unread before, each site hard-coding level 1) |
| `client.rs` | IdentityClient for identity resolution, revelation, and management; both `ls_identity` parsers decode a token lock-before alone through one function, `decode_token` (`PushDrop::decode_before`), as `IdentityClient.ts:773` does, a lock-after token skipped (#537); `tests/identity_lock_position_537.rs` pins the skip but not the position alone, since #544's token check refuses every lock-after layout too (green with `decode_token` on `PushDrop::decode`), so the position is pinned at the call by `client_decode_token_744_tests.rs` (#744); since #544 both authenticate the token before reading its certificate (`client_token.rs`); since #553 both run the reference discovery's record checks first (`client_record.rs`), every refusal a skip, never an `Err` for the resolution; since #721 both read the output from the BEEF's subject (`Transaction::from_beef(_, None)`: the atomic txid, else the last transaction on the wire), as the toolbox's evidence loader does (`TransactionEvidence.ts:116-126`), where they read `beef.txs.first()`, the parent of every writer's order (`tests/identity_beef_subject_721.rs`); since #730 both take the subject from `evidence::admit`, the reference's evidence check, in place of `Transaction::from_beef`: a refused output skipped, a limit the discovery's `IdentityError` in the reference's words (`evidence.rs`); since #737 `resolve_by_identity_key` parses every output of the answer in order through the same parser before it answers, as the toolbox's `parseResults` walks them (`identityUtils.ts:671-707`), a limit anywhere failing the call, and keeps the certificates whose subject is the asked key (lower-cased on both sides, the wallet's `filterCertificatesByIdentityKey`, `identityUtils.ts:247-255`, `Wallet.ts:1012`; the reads' fold), where it read `outputs[0]` alone (a skipped first output ended it with `None`, another subject's certificate answered it); since #737's list (the owner's word of 2026-11-04 13:5xZ) it returns `Vec<DisplayableIdentity>`, every one of them in the trust step's order (`client_trust.rs`), as the reference's `resolveByIdentityKey` returns its list (`IdentityClient.ts:559-591`), where it returned the earliest (`Option`); an answer with none admitted the empty list, a stored contact (with `override_with_contacts`) a one-element list; the trust settings and the page unported, the order the answer's at the parser's one trust (`tests/identity_resolve_737.rs`, two certifiers at unequal trust its stated test; `resolve_by_attributes` a list by its own rule, unchanged); since #739 `discover_certificates` and `discover_certificates_by_type` keep only certificates whose subject is the asked key, through the same private comparison (`is_asked_subject`, shared by the three by-key doors) after the same walk (one private `discover_of_subject`), where they returned another subject's: `discover_certificates` the door of the BRC-100 wallet's `discoverByIdentityKey` (`Wallet.ts:966-1015`, the filter at `:1012`), a parity rule, the trust step, the page and the argument check of that door unported (the #739 parity note); `discover_certificates_by_type` without a counterpart (`tests/identity_discover_subject_739.rs`); since #744 `discover_certificates_by_type` keeps of those only the certificates whose type is the asked one, applied on the shared walk after the subject filter, `type_base64()` compared exactly with the asked text (canonical base64 of 32 bytes on every token read, #553): this crate's own rule, the reference having no by-type door (`tests/identity_discover_type_744.rs`); since #746 `query` keeps, after the same parse of every output, only the certificates matching every field its question carries (`is_asked_certificate`): `identity_key` through `is_asked_subject`, `certificate_type` as `type_base64()` exactly, `certifier` (one key, `Option<String>`) as the certificate's certifier hex against the asked text lower-cased; a field unset filters nothing (an unset `certifier` still asks the default SocialCert certifier of the overlay, unfiltered), `attributes` unchecked; this crate's own rule, the reference having no such door (`tests/identity_query_filters_746.rs`); since #752 the two by-type questions send the type as `certificateTypes: [type]` beside `identityKey`, the key and shape the reference overlay's `ls_identity` allowlist admits (`IdentityLookupService.ts:74-82,136-143` at `ts-stack@edf6e03`), where `certificateType`, a key it refuses for the whole question, went before (`tests/identity_question_752.rs`); since #754 `discover_certificates` asks `{ identityKey }` alone, where it sent `certificatesOnly: true`, a key the same allowlist refuses for the whole question (`IdentityLookupService.ts:74-82`); the reference wallet's `discoverByIdentityKey` adds `certifiers`, its trust settings' keys (`Wallet.ts:992,1004`), and with no trust settings here none is named (`tests/identity_question_754.rs`, which also passes every by-key door's question through the allowlist); since #751 `query` with `attributes` and `resolve_by_attributes` keep only the certificates whose decrypted fields match the map sent (`client_attributes.rs`; `query`'s filter `client_attributes::is_asked`, where `is_asked_certificate` lived, the attributes beside #746's three fields), the reference wallet's `filterCertificatesByAttributes` (`Wallet.ts:1069-1082`), where every admitted certificate was kept; `resolve_by_attributes`' lone attribute sent and judged as `any` (#394's pin kept), `limit` and `offset` sent before the filter (`tests/identity_query_attributes_751.rs`); since #756 `query` refuses a question the reference overlay refuses whole before the network, in its words (`query_bounds.rs`, `tests/identity_query_bounds_756.rs`); since #751's fold `query` sends its attributes in insertion order through `query_ordered` (its other members' bytes unchanged, sorted), as `resolve_by_attributes` does (`tests/identity_lookup_attribute_order_394.rs`); since #818b (#905) `resolve_by_identity_key`, `discover_certificates`, `discover_certificates_by_type` and `resolve_by_attributes` refuse before any lookup what the reference's wallet door refuses, in its words (`client_door_args.rs`), and the three by-key doors compare a certificate's subject with the key the validated text names (`Wallet.ts:1012`: a space-padded key keeps its subject's certificate), `is_asked_subject` left to `query` alone (`tests/identity_door_args_818b.rs`) |
| `client_attributes.rs` | #751: `keeps`, the reference wallet's `filterCertificatesByAttributes` (`ts-stack@edf6e03` `packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:140-293`) over one certificate's decrypted fields, function for function: `normalize` (`normalizeIdentitySearch`, JavaScript's `trim` and `\s`), `fuzzy_matches` (`identityFuzzyMatches`, the line split and ECMA-262's non-unicode `Canonicalize` written out over UTF-16 units), `any_matches` (the fields in `Object.entries` order, `js_order`, also read by `query_bounds.rs` since #751's fold, `profilePhoto` and `icon` left out, two units fuzzy), `text_matches` (`fold`: NFD, `\p{Mn}` removed, lower case; `text_tokens` with the stop words; `query_parts` the `/-?"([^"]*)"\|[^\s"]+/g` scanner; `part_match`); `is_asked`, `query`'s filter (#746's subject, type and certifier, moved from `client.rs`, and the attributes). Unit pins `client_attributes_751_tests.rs` and, since #818, `client_attributes_818_tests.rs` |
| `client_attributes_751_tests.rs` | #751's unit pin (`#[cfg(test)]`, a child of `client_attributes.rs`): the 52 cases of `tests/vectors/identity_attributes_751.json` (42 until #818's five, 47 until its fold's five) (recorded by `tests/support/identity_attributes_751.mjs`, the reference's `filterCertificatesByAttributes` under Node v22.18.0) judged by `keeps` to the reference's kept indices; compile-RED on `545eb36f` (the matcher absent) |
| `client_attributes_818_tests.rs` | #818's unit pins (`#[cfg(test)]`, a child of `client_attributes.rs` beside the #751 module): three rules of the matcher no recorded case held, each read by name from the five cases the #751 recorder added: `fuzzy_repeated_token` (a repeated token searched from where the last match ended, `identityUtils.ts:154-158`; `a a` keeps `a a` and `aa`, never `a` or `ba`), `fuzzy_paragraph_separator` (U+2029 ends a line, `:147`), and `any_index_name_u32_max`, `any_index_name_leading_zero`, `any_index_name_plus_sign` (`js_order` walks ahead only a canonical array index: `4294967295`, `01` and `+1` keep their place; the u32 bound beside a third field, two fields alone reading the same either way). RED in a scratch copy of the tip under `cursor = *at`, U+2029 dropped from the split, and `js_order`'s filter dropped, cut to `n != u32::MAX` (the two non-canonical names) and cut to `n.to_string() == name` (the u32 bound). The fold's five tests (the strength read's S1 to S5, each a mutation that passed every test, the lib's and the 39 `tests/identity_*.rs` binaries', until its case was recorded), by name from five more cases: `fuzzy_token_longer_than_one_unit` (`ab bc` over `abc`, `abbc`, `ab bc` keeps `[1, 2]`: the cursor moves by the token's length, `:156`), `fuzzy_lone_carriage_return` (a lone CR ends a line and takes nothing after it, `:147`), `fuzzy_second_line_from_its_start` (each line searched from its start, `:152`), `any_index_name_below_u32_max` (`4294967294` an array index) and `any_two_index_names` (`2, 1` and `10, 9` walked ascending by number). RED in a scratch copy of the tip under `cursor = at + 1`, the CR arm's `!=` and `\|\|`, the cursor kept across lines, the guard at `n < u32::MAX - 1`, and the sort key `(0, 0)` or the name's text |
| `query_bounds.rs` | #756: `check`, the reference overlay's `ls_identity` question bounds (`ts-stack@edf6e03` `packages/overlays/topics/src/identity/IdentityLookupService.ts:83-123`, the words `shared/queryValidation.ts`) over the question `query` sends, in the overlay's order (`limit`, `offset`, `identityKey`, a set certifier as `certifiers[0]`, a set type as `certificateTypes[0]`, 1 to 44 bytes then base64 of 32 bytes through `reveal::base64_parameter`, since the fold on the captain's ruling of 2026-11-09, #746's unpadded-type assertion moved to the refusal; the attributes' count, then each name and value in `js_order`, the order `Object.entries` walks the text `query` sends, array-index names ahead, since #751's fold), the key's point read by `PublicKey::from_hex` (#498); a refusal `Error::IdentityError` in the overlay's whole message, nothing sent. Hardening, not parity (`query` has no reference counterpart; the reference's other doors check through its wallet, #818b). Pinned by `tests/identity_query_bounds_756.rs` (since #818 an `03` key and certifier among its recorded cases, `a_key_tagged_03_is_admitted_818`: a check admitting `02` alone passed every test until then). `query` calls `check`; since #818b `discover_certificates_by_type` calls its type rule (`certificate_type`, the overlay's words, this crate's own: no reference door takes a type). The other doors make the reference's wallet door's check since #818b (`client_door_args.rs`, the row below), where they sent the caller's map, key and type and read the overlay's refusal as an empty answer with the host charged (#818's record) |
| `client_door_args.rs` | #818b (#905): the by-key, attribute and discovery doors' argument checks, a child of `client.rs`. The reference's `IdentityClient` hands its arguments to its wallet (`ts-stack@edf6e03` `IdentityClient.ts:569`, `:614`), whose `WalletClient` validates them before it connects (`WalletClient.ts:509-511`, `:524`; the toolbox's `Wallet.ts:971`, `:1029`): `identity_key` is `wallet::validate_discover_by_identity_key_args` on the asked key (`resolve_by_identity_key`, `discover_certificates`, `discover_certificates_by_type`; the key it names the subject filter's, `Wallet.ts:1012`, the question carrying the text as given, `:1004`), `contact_key` the contacts manager's `validateIdentityKey` ahead of the contact read with `override_with_contacts` (`ContactsManager.ts:83-94`, through `contacts::contact_identity_key`; `Error::IdentityError` in its words), `attributes` `wallet::validate_discover_by_attributes_args` on `resolve_by_attributes`' map as given (before the contacts load and the lone attribute's `any`), `certificate_type` `query_bounds::certificate_type` for the by-type door. A refusal before any lookup, no host charged. Stated: a padded key sent as given; the contact read from the cache alone; with contacts a map refused before the contacts load where the reference loads them before it refuses; the by-type rule this crate's own. Pinned by `tests/identity_door_args_818b.rs` against `tests/vectors/identity_door_args_818b.json` (recorded by `tests/support/identity_door_args_818b.mjs`) |
| `client_trust.rs` | #737's list: `ordered_by_trust`, the toolbox wallet's `transformVerifiableCertificatesWithTrust` (`ts-stack@edf6e03` `wallet-toolbox/src/utility/identityUtils.ts:313-382`) over the asked subject's certificates as far as this crate holds it: the leading 256 (`MAX_IDENTITY_RESULTS`, `:22`), one per type, serial number and certifier (`:360-362`), the stable sort by `certifier_info.trust` descending (`:378`), ties in the answer's order; the trust settings' drops and threshold (`:333-334,369-374`) not ported (no settings here, #754's record). Read by `resolve_by_identity_key` alone. Its three unit tests pin the sort, the repeat rule and the cap on certificates built in the test (the parser's trust one constant, so the door cannot show the sort); RED in a scratch copy with the repeat rule removed and the sort ascending |
| `evidence.rs` | #730: `parse_evidence`, the reference's `parseEvidence` (`ts-stack@edf6e03` `packages/sdk/src/transaction/TransactionEvidence.ts:93-201`), run by both `ls_identity` parsers before they read an output, as the toolbox's `IdentityEvidenceVerifier` runs it (`identityUtils.ts:600-634`): the 1 MiB bytes bound, `Beef::from_binary` (strict, as `fromBinaryStrict`), 256 transactions, the target (the atomic txid, else the last entry), the output index, then `assertUnconfirmedGraph`'s walk over the BEEF (each input's source the entry under its txid, proven by a BUMP carrying its txid, `findBump`; a proven transaction ends its branch, an unproven one without inputs, an input without its source, a second spend of one outpoint refused; 4096 inputs and 256 KiB of script across the graph), the reference's default limits as constants named for theirs; no BUMP index read against its leaf (`TxidNotInBump` is `verify_structure`'s and the streaming reader's, not this door's). `Refusal { code, site }` internal (`invalid-evidence` or `limit`, the reference's line); `admit` skips an `invalid-evidence` output and answers a `limit` as `IdentityError("Transaction evidence: limit")`, as the toolbox's verifier rethrows it (`:630-634`). Not ported: the coordinator's `tx.verify` against a chain tracker (`TransactionEvidenceCoordinator.ts:317-345`), the #553 row's residue. Pinned by `tests/identity_evidence_730.rs` and the unit module `evidence_730_tests.rs` (the vector's twelve BEEFs and the #725 and #728 shapes, code and line the reference's; the builder `tests/support/identity_evidence_730.rs` shared with the door test); since #735 `admit` compares the output's `txid` hint (`OutputListItem::txid`) with the subject as `loadEvidenceTransaction` does, lower-cased (`TransactionEvidence.ts:123-124`), and on a disagreement reads the subject and counts it in the client's `HintContradictions`, read by the public `IdentityClient::txid_hint_contradictions` (an output the check refuses not counted), by the owner's word of 2026-11-04 13:5xZ, where the reference refuses it `invalid-evidence` and skips the output (the stated divergence, ts-stack #1482; `tests/identity_evidence_hint_735.rs`); stated with it (the fold): a disagreeing hint on an output whose graph passes a limit checked after the hint (`:187`) is skipped by the reference and fails the whole discovery here with nothing counted; the count is per parse (an output read by both parsers counted twice) and before the token's and record's checks; since #796 a lying copy the resolver's merge displaces for an agreeing or hintless one never reaches `admit`, so it is counted by `LookupResolver::txid_hint_contradictions` alone and this count reads 0 for it, where it read 1 before #796; a lying copy the merge keeps (the earliest of its key, no agreeing or hintless copy answered) is counted by both, and one that arrives after a held copy of its key by the resolver alone, where before #796 it was counted nowhere (the parser reads the merged answer alone; `tests/identity_hint_displaced_818.rs`, #818, pins the displaced and the kept copy, `tests/lookup_hint_merge_796.rs` the resolver's count of a copy after a held one); a client built by `IdentityClient::new` has no door to the resolver's count, one built by `with_resolver` over a resolver the caller keeps reads both; since #818 the transactions bound's count of entries, a repeated txid each time it is written (`beef.txs.len()`, `TransactionEvidence.ts:117`), pinned by `evidence_818_tests.rs` |
| `evidence_736_tests.rs` | #736's unit pins (`#[cfg(test)]`, included from `evidence.rs` beside the #730 module): the six BEEFs of `tests/vectors/identity_evidence_736.json` (recorded by `tests/support/identity_evidence_736.mjs`, the builder `tests/support/identity_evidence_736.rs` shared with `tests/identity_evidence_736.rs`) judged by `parse_evidence` to the reference's code and line; the inputs and script-bytes bounds running sums over the visited graph, a proven parent's scripts counted (`TransactionEvidence.ts:166-171`), each transaction inside both bounds alone; one parent written raw and txid-only, both entries held and the later the index's (`Beef.ts:516-524`), `admit` skipping or reading it. RED in a scratch copy with the sums per transaction (3 of 4) and with the index keeping the earlier entry (2 of 4) |
| `evidence_741_tests.rs` | #741's unit pin (`#[cfg(test)]`, included from `evidence.rs` beside the #736 module): the two BEEFs of `tests/vectors/identity_evidence_741.json` (recorded by `tests/support/identity_evidence_741.mjs`, the builder `tests/support/identity_evidence_741.rs` shared with `tests/identity_evidence_741.rs`) judged by `parse_evidence` to the reference's code and line: the inputs bound a running sum over two unproven branches of one proven grandparent (4097 `limit` at `TransactionEvidence.ts:170-171`, 4096 read), each path alone at most 2050. RED in a scratch copy with the sums carried per path (a recursive walk), where #736's single-chain pins stay green |
| `evidence_748_tests.rs` | #748's unit pin (`#[cfg(test)]`, included from `evidence.rs` beside the #741 module): the two BEEFs of `tests/vectors/identity_evidence_748.json` (recorded by `tests/support/identity_evidence_748.mjs`, the builder `tests/support/identity_evidence_748.rs` shared with `tests/identity_evidence_748.rs`) judged by `parse_evidence` to the reference's selected txid: one grandparent G reached through two unproven parents, unproven over a proven GG (without the visited set `invalid-evidence` at `TransactionEvidence.ts:149`) or proven with 4092 inputs (4096 once; without the set 8188, `limit` at `:170-171`). RED in a scratch copy with the set's skip removed, as #736's and #741's pins are too |
| `evidence_731_tests.rs` | #731's unit pin (`#[cfg(test)]`, included from `evidence.rs` beside the #748 module): the four BEEFs of `tests/vectors/identity_evidence_731.json` (recorded by `tests/support/identity_evidence_731.mjs`, the builder `tests/support/identity_evidence_731.rs` shared with `tests/identity_evidence_731.rs`), an Atomic prefix naming X with X written raw and txid-only in both orders, X proven or unproven: `Beef::from_binary` keeps both entries in the written order (the collect mode reorders nothing), the later one the index's (`Beef.ts:516-524`), `parse_evidence` `invalid-evidence` at `TransactionEvidence.ts:120-121` for raw then txid-only and X for txid-only then raw, `admit` skipping or reading. RED in a scratch copy with `push_tx` keeping the earlier entry (4 of 5), the target's raw entry taken (2 of 5) and the collect mode inserting a txid-only entry before its raw one (2 of 5, the wire order) |
| `evidence_818_tests.rs` | #818's unit pin (`#[cfg(test)]`, included from `evidence.rs` beside the #731 module): the two BEEFs of `tests/vectors/identity_evidence_818.json` (recorded by `tests/support/identity_evidence_818.mjs`, the builder `tests/support/identity_evidence_818.rs`), an Atomic prefix naming the proven subject over txid-only entries with `00..01` written twice, rebuilt to the recorded SHA-256 and judged by `parse_evidence`: 255 distinct txids in 256 entries read, 256 distinct in 257 entries `limit` at `TransactionEvidence.ts:117` (the reference counts `beef.txs.length`; #730's bound shapes hold distinct txids alone). RED in a scratch copy of the tip with the bound over distinct txids (`unwrap_err()` on `Ok`, the over-bound shape read) |
| `client_token.rs` | #544: `is_authenticated_token`, the revocation's checks on a revelation token (`ts-stack@edf6e03` `IdentityClient.ts:773-815`: exactly two fields, the canonical signed envelope, the locking key, the field signature) with the key and the signature the subject's, as the toolbox's discovery reads a published token (`identityUtils.ts:497-559`: the anyone wallet's key for counterparty the subject, `verifySignature` as anyone); a token that fails skipped by both parsers; pinned by `tests/identity_envelope_544.rs` |
| `client_decode_token_744_tests.rs` | #744's unit pin (`#[cfg(test)]`, included from `client.rs`): the reference's own revelation token (#553's `reference` case) relocked after its fields, read by `PushDrop::decode` with the same fields and refused by the token check, refused by `decode_token` by the position alone; RED with `decode_token` on `PushDrop::decode`, where `tests/identity_lock_position_537.rs` stays green |
| `revoke_decode_746_tests.rs` | #746's unit pin (`#[cfg(test)]`, included from `revoke.rs`), #744's at the revocation: the reference's own revelation token (#553's `reference` case) relocked after its fields, read by `PushDrop::decode` with the same fields and refused by `is_canonical_signed_pushdrop`, refused by `decode_revocation_token` by the position alone; RED with the function on `PushDrop::decode` |
| `client_record.rs` | #553: `read`, the checks the reference's discovery runs on a revelation token before it authenticates it (the toolbox's `decodeIdentityOutput`, `ts-stack@edf6e03` `wallet-toolbox/src/utility/identityUtils.ts:497-522`, reached by the SDK's `IdentityClient.resolveByIdentityKey`/`resolveByAttributes` through the wallet's discovery, `IdentityClient.ts:559-655`, `Wallet.ts:904-1010`): two fields, the certificate 1 to 256 KiB, the signature 8 to 80 bytes; then `certificateRecord` (`:87-132`): the bytes as `toUTF8Strict` reads them (one leading BOM dropped), a JSON object of exactly the eight members, `fields` and `keyring` objects of 1 to 100 names, every keyring name a field's and every keyring value a string of at most 2048 UTF-16 units; then the members as a certificate, under the text rules of the verify step that skips the reference's record (`Certificate.ts:425-440`): `type` and `serialNumber` canonical base64 of 32 bytes (`canonical_id`, `:233-238`), strict keys, the revocation outpoint a string of a 64-hex txid and an index `0` or a plain decimal at most `0xffffffff` (`outpoint`, `:257-270`), every field value a string (`:63-72`), the hex signature (the cold review's fold). `None` skips the token, as every failure in `decodeIdentityOutput` does (`:555-557`). Not ported, stated in the #553 parity note: the toolbox wallet's evidence verification (its `tx.verify` against a chain tracker; the parse, the limits and the unconfirmed-graph walk run since #730, `evidence.rs`, so the 256 KiB script bound refuses the whole discovery here too), the anyone decryption's success and non-empty result (`:551-552`); `JSON.parse`'s lone surrogate escapes since #566 (`client_record_lenient.rs`). Pinned by `tests/identity_certificate_record_553.rs` |
| `client_record_lenient.rs` | #566: `read`, reached from `client_record::read` only when `serde_json` refuses the record's text: each string read as `serde_json` reads a byte string, in WTF-8 (a lone surrogate escape its own three bytes, where a `String` refuses it), as `JSON.parse` keeps a lone code unit (`ts-stack@edf6e03` `wallet-toolbox/src/utility/identityUtils.ts:88`); the keyring names judged against the field names unit for unit (`:122-125`); a keyring value or a revealed field's value with a lone unit skipped (no base64: the reference's anyone decryption fails, `:551-552`, `VerifiableCertificate.ts:182-191`; the field value the cold review's); `serde_json` 1.0.125 the floor (`Cargo.toml`); every string then held with each lone surrogate as U+FFFD, the bytes `TextEncoder` writes under the certificate's signature (`Certificate.ts:73-75,280-296`); two names one `String` would hold skipped, and a name whose lone unit ICU 77.1 sorts before a private-use or unassigned BMP character above U+DFFF beside it, where this crate's collation sorts U+FFFD after it (the #566 parity note). Units in `client_record_lenient_tests.rs` (an escape cut at the end, a high before a non-low, a low alone, without a panic); pinned by `tests/identity_lone_surrogate_566.rs` |
| `token_envelope.rs` | `is_canonical_signed_pushdrop`, the five-chunk signed two-field envelope the reference checks for an identity token (`assertCanonicalIdentityTokenScript`, `IdentityClient.ts:123-147`) and a contact token (`assertCanonicalSignedPushDrop`, `ContactsManager.ts:218-241`); shared by `revoke.rs`, `client_token.rs` and `contacts_auth.rs` (moved from `revoke.rs` by #544) |
| `client_field_value_261_tests.rs` | The intake witnesses of #261 (`#[cfg(test)]`, included from `client.rs`): the reference-issued certificate of `tests/vectors/certificate_field_value_261.json`, published for anyone as the reference publishes it, parses, verifies and decrypts through both parsers; one output with a malformed signature among good ones is skipped and the resolution goes on (`IdentityClient.ts:823-825`); and #268's: a certificate signed over `<txid>.0`, published with its outpoint as the txid alone (the reference's default form), parses through both parsers to index 0 and verifies; and #498's re-review's: a published subject or certifier in a hybrid or odd-length form skipped by both parsers (`a_published_certificate_key_in_a_lenient_form_is_skipped_498`), the keys read as the reference's `Certificate.toBinary` reads them (through `auth::certificates::read_to_binary_key` since #585); and #585's (`client_to_binary_key_585_tests.rs`, a child module): the vector `tests/vectors/certificate_to_binary_key_585.json`'s eight subject and eight certifier texts (canonical, upper case, space-padded, uncompressed, hybrid, odd length, x above p, x no point's), each read by both parsers exactly when the reference's `verify` answers `true` (RED on `76bbe036`: the uncompressed subject and certifier read), and the reader's refusals in `toBinary`'s words |
| `client_to_binary_key_585_tests.rs` | #585's witnesses (`#[cfg(test)]`, a child of `client_field_value_261_tests.rs` for its `publish_by`): see the row above; the recorder is `tests/support/certificate_to_binary_key_585.mjs` |
| `client_beef_subject_725_tests.rs` | #725's parser pin (`#[cfg(test)]`, a child of `client_field_value_261_tests.rs`): the five BEEFs of `tests/vectors/identity_beef_subject_725.json` handed to both `ls_identity` parsers directly, each read or skipped as `parseResults` decides, the txid-only parent shapes skipped since #730 (read before, #553's evidence-layer residue; RED on `11bb04ce` on those two); the absent atomic txid, which `LookupResolver`'s dedup drops before any parser, is pinned here; RED on `0d8546c0` on all five |
| `client_beef_subject_728_tests.rs` | #728's parser pin (`#[cfg(test)]`, a child of `client_field_value_261_tests.rs`): the five BEEFs of `tests/vectors/identity_beef_subject_728.json` handed to both `ls_identity` parsers directly at their recorded output index, each skipped as `parseResults` skips it, the parent whose BUMP names another txid since #730 (read before, #553's evidence-layer residue; RED on `11bb04ce`); the txid-only subjects, which `LookupResolver`'s dedup drops before any parser, are pinned here; the vector's count (five) asserted; RED on `0d8546c0` on three (the txid-only entry last and the hand Atomic prefix read, the other-txid BUMP skipped) |
| `reveal.rs` | The checks `publicly_reveal_attributes` makes around its wallet calls (#307), the reference's in its order and words (`ts-stack@edf6e03` `IdentityClient.ts:420-499`): a field named `__proto__`, `constructor` or `prototype`, no fields, no names, more than 100, a name over 50 bytes or with a display control, empty or unsafe, repeated or absent from the certificate, then the master certificate's signature (read from the wallet certificate's JSON, `Certificate::verify`), all before any wallet call; after `proveCertificate`, a keyring carrying an unsafe name (`proof result keyringForVerifier contains an unsafe field`), then one naming other fields than those asked, then each value as `validateBase64String(.., 1, 2048)` reads it (trimmed as JavaScript trims, base64 by shape, 1 to 2048 bytes), the trimmed values judged and published in the wallet's key order (`:485`, #385). `IdentityError` in each case but the value's, `WalletRefusal` of the `InvalidParameter` class in `WERR_INVALID_PARAMETER`'s words; pinned by `tests/identity_reveal_verifies_307.rs`. Then `identity_token` (#310): the reference's `PushDrop.lock([json], protocolID, keyID, 'anyone', true, true)` (`IdentityClient.ts:502-509`, `PushDrop.ts:146-202`), getPublicKey for anyone with `for_self: true`, createSignature over the JSON for anyone (through `PushDrop::lock_with_wallet` since #816: the key text judged before the signature is asked, `tests/pushdrop_lock_key_order_816.rs`), the JSON `{...certificate, keyring}` in `WalletCertificate`'s member order, the fields in the order held, the keyring in the wallet's (#385): the reference's bytes for its certificate and keyring, admitted by the overlay's identity reader; pinned by `tests/identity_reveal_rest_310.rs`. The createAction after it (in `client.rs`, #315) sends the reference's arguments alone (`IdentityClient.ts:513-528`): the description, one output of satoshis, locking script and output description, `randomizeOutputs: false`; no label, tag, `signAndProcess` or `acceptDelayedBroadcast`, left to the wallet; pinned by `tests/identity_reveal_create_action_315.rs`. The revocation (`revoke.rs` since #327) sends the reference's createAction (`IdentityClient.ts:845-863`: the description, `inputBEEF`, one input of description, outpoint and `unlockingScriptLength: 74`, `randomizeOutputs: false`, `acceptDelayedBroadcast: false`, `noSend: true`; no label, no `signAndProcess`) and signAction (`:896-911`: the reference as createAction answered it, its base64 text, and `returnTXIDOnly: false`), and every wallet call of the client carries the configured originator or none (`""`, `IdentityClient::originator`; the reference's `:369-377`); pinned by `tests/identity_wallet_calls_318.rs` |
| `revoke.rs` | `revoke_certificate_revelation`, the reference's `revokeCertificateRevelation` step by step in its words (#327; `ts-stack@edf6e03` `IdentityClient.ts:705-950`): the serial number as base64 of 32 bytes (`reveal::base64_parameter`, `WERR_INVALID_PARAMETER`), getPublicKey for the identity key and the token's key, the `ls_identity` answer (`Failed to get lookup result`; at most 10000 outputs and 16 MiB of BEEF), each output authenticated or skipped (the BEEF's subject, the output at the lookup's index, the canonical signed PushDrop locked to the token's key, the JSON's serial number and subject, `Certificate::verify` of its seven members, verifySignature over the token), none: `No authenticated revelation output matches the requested certificate.`; every authenticated output spent at its own index (the signable transaction's one matching input, `revelationInputOutpoint`), the signed transaction checked against the signable one (`assertRevelationTransactionTemplate`, the input, its script, the txid), broadcast on `tm_identity` (`IdentityClient::with_broadcast_facilitator` the seam), abortAction with the reference on any failure after createAction, the spend under the shared `overlay::wallet_retry` rule (#340); pinned by `tests/identity_revocation_checks_327.rs`; the token decoded lock-before alone through one function, `decode_revocation_token` (`PushDrop::decode_before`, `IdentityClient.ts:773`), its position pinned at the call by `revoke_decode_746_tests.rs` (#746), since the token check refuses every lock-after layout too |
| `token_maps.rs` | An identity token's `fields` and `keyring` read in the order of its JSON text (#394), where the `serde_json::Value` the parsers read the rest from sorts its keys: a member not an object empty, a value not a string skipped, as the `Value` reading did; both parsers (`parse_output_to_certificate`, `parse_output_to_verifiable_certificate`) take their maps from it |
| `contacts.rs` | ContactsManager and cached CRUD coordination (237 lines); action construction and signing are in contacts_actions.rs. `protocol()` reads `ContactsManagerConfig::protocol_id`, the reference's `[2, 'contact']` by default (`ContactsManager.ts:30`), for every contact key: the identity tag's HMAC here (`create_identity_tag`, `:572-583`), was `[1, 'contact']` until #542 (`tests/identity_contacts_protocol_542.rs`). Since #904 `add_contact` returns every wallet failure (the tag HMAC, the tagged listing, the create or the update) as the reference's `saveContact` lets it through (`ContactsManager.ts:536-566`), and caches the contact after the chain alone; the reference's cold load of the basket before the tagged listing (`:529-531`) is not ported (stated). |
| `contacts_actions.rs` | Contact create/update/removal and the shared PushDrop data request (#454) (485 lines). The encryption and the lock's getPublicKey (`contact_lock`, `ContactsManager.ts:748-772`) and the spend's signature (`contact_unlock`, `:821-830`) under the configured protocol, `[2, 'contact']`, since #542; since #544 the token is the reference's signed two fields (`contact_lock`: `PushDrop.lock([ciphertext], protocol, keyID, 'self')`, getPublicKey `forSelf` false, createSignature over the ciphertext; through `PushDrop::lock_with_wallet` since #816, the key text judged before the signature is asked, `tests/pushdrop_lock_key_order_816.rs`), and the update and removal lookups authenticate every listed output before a spend (`find_existing`, `ContactsManager.ts:587-626`; `remove_listed`, `:941-959`), refusing in the reference's words. Since #904 (`tests/contacts_listed_spend.rs`): `listed_source` is `#readListedSource` whole (`:633-659`: the BEEF bounded, the transaction read by the outpoint's txid, its output, satoshis and script, in the reference's words), one reading serving the authentication and the spend, where the spend read the BEEF's leading entry (the parent of an unmined token) at the listed index; `sign_bound` finds the input bound to the outpoint (`#findBoundInput`), signs it there and keys the spend by it, where it signed input 0 and keyed 0; `spend_listed` aborts the action by its reference on any failure after createAction (`#abortPartialAction`, `:738-745`), the failure returned as it came; the requests the reference's (`Add Contact`, `Update Contact`, `Delete Contact`, `Spend previous contact output`, `Spend contact output to delete`, `Contact: <name>`, `Updated Contact: <name>`, the removal's `outputs: []`, no label, `{ acceptDelayedBroadcast: false, randomizeOutputs: false }`: no `signAndProcess`, no `noSend`); `remove_contact` asks the wallet whatever the cache holds and removes the cache entry after the spend or when nothing listed stores it (`:891-938`), every wallet failure returned (`tests/contacts_wallet_failures.rs`): at the removal the HMAC's and the listing's as they came, and every failure past the listing (the decrypt, createAction, signAction, the checks) under `Unable to authenticate or remove a contact output`, as `removeContact` wraps them (`:908-918`). |
| `contacts_auth.rs` | #544: `authenticate_contact`, the reference's `#authenticateContactScript` (`ContactsManager.ts:431-466`: two fields, the ciphertext 1 to 65 KiB plus 1 KiB, the signature 8 to 80 bytes, the canonical envelope, the lock the wallet's key for the key ID and self, `verifySignature` over the ciphertext), and `open_contact` (decrypt, `#parseContactPlaintext`); since #718 the token read as the reference's `PushDrop.decode` reads it (`decode`: the decode's own words for no first chunk, a first chunk without data and a key `Point.fromDER` refuses, then `PushDrop::decode_reference_before`, the second chunk never read), so a key alone or a token without `OP_CHECKSIG` second reaches the count, the bounds and the envelope in the reference's order and words; pinned by `contacts_auth_718_tests.rs` |
| `contacts_auth_718_tests.rs` | #718's unit witness (`#[cfg(test)]`, a child of `contacts_auth.rs`): ten shapes of `tests/vectors/identity_contacts_canonical_718.json` (recorded by `tests/support/identity_contacts_canonical_718.mjs`, the reference's `getContacts` drop words under Node v22.18.0), each built by this crate's PushDrop writer to the recorded SHA-256, refused by `authenticate_contact` in the reference's words; 8 of 10 RED with the read put back to `decode_before` |
| `contacts_record.rs` | #544: `validateContact`'s record (`ContactsManager.ts:171-198`): the seven display fields with the reference's spellings and an optional `metadata`, any other member refused, each field's bounds and words (`boundedString`, `validateIdentityKey`, `safeResource`, `safeNavigation`, `sanitizeMetadata`); `record_of` maps a `Contact` onto it (`notes` and `tags` in `metadata`, the three badges as held, empty where unset, since #552; `added_at` out of the token), `contact_of` back (the badges kept, #552; `added_at` the cache's); the record's `abbreviatedKey` read into `Contact::abbreviated_key` and written back as held since #559, `to_displayable_identity`'s form only when it is `None`; `read_key_id` the reference's `#readKeyID` (`:414-429`) |
| `contacts_cache.rs` | Cache refresh, contact decoding and search, extracted without changing the public paths (180 lines); a stored contact decoded lock-before alone, as `ContactsManager.ts:432` does, a lock-after token dropped before decrypt (#537, `tests/identity_contacts_lock_position_537.rs`). The decryption (`decode_cached_contact`, `ContactsManager.ts:494-501`) under the configured protocol, `[2, 'contact']`, since #542: the reference's record decrypts here. Since #544 each listed output is read as `#decryptContactOutputs` reads it (`:480-503`: the key ID, the authentication, the record), a refused one dropped; the saved-at time kept from the cache. Since #904 a failed listing is the caller's error and a listing past 1000 outputs refused in the reference's words (`#loadContactsFromWallet`, `:353-368`), where it refreshed to none; since #904's fourth fold a forced refresh whose listing fails leaves the cache empty and not loaded, as `getContacts`' `#invalidate` before its load leaves it (`:321`, `:343-347`; dropped on the failure here, the decode reading each saved-at time from the cache during the load). Since #904's eighth fold the cache (`ContactsCache` in `contacts.rs`) holds the contacts in a `Vec` in the reference's array order (`ContactsManager.ts:326-328`, `:376`, `:532-534`, `:934`: a load's listing order, a new contact appended, an update in place, a removal filtering), with an index to each key's first position for a lookup by key; a plain read, `search_contacts` and `get_contacts_by_tag` answer that order, where they answered a `HashMap`'s (`tests/contacts_replay.rs`, every answer compared in order). |
| `contacts_spend.rs` | #904: the checks the reference makes around a contact spend (`ContactsManager.ts:661-745`): `parse_atomic` (`#parseAtomicTransaction`, the bytes bounded at 16 MiB), `input_outpoint` and `find_bound_input` (`#inputOutpoint`, `#findBoundInput`: the one input at the outpoint, else `Contact transaction does not spend the exact contact outpoint once`), `assert_template` (`#assertTransactionTemplate`), `require_contact_output` (`#requireContactOutput`), `check_signed` (the signed transaction's checks of `:841-851` and `:1008-1015`) and the update's and removal's words (`UPDATE`, `DELETE`). |
| `types_tests.rs` | The unit tests of `types.rs`, moved out unchanged by #552 (the ratchet holding `types.rs` at its size while `Contact` gained its badge fields). |
| `contacts_tests.rs` | Existing contact unit tests, separated from production (267 lines). Since #904 they run over `Answering`, a ProtoWallet answering an empty listing and a finished create, where the ProtoWallet's refused listOutputs and createAction had been swallowed. |

## Feature Flag

```toml
[features]
identity = ["auth", "overlay"]
```

The identity feature depends on both `auth` (for certificate types) and `overlay` (for network communication); `indexmap` reaches it through `wallet` (#385), so it needs nothing of its own for its ordered maps (#394).

## Public Exports

```rust
// From mod.rs re-exports
pub use client::IdentityClient;
pub use contacts::ContactsManager;
pub use types::{
    // Type aliases
    Base64String,
    CertificateFieldNameUnder50Bytes,
    OriginatorDomainNameStringUnder250Bytes,
    PubKeyHex,
    // Broadcast types
    BroadcastFailure,
    BroadcastResult,
    BroadcastSuccess,
    // Core types
    CertifierInfo,
    Contact,
    ContactsManagerConfig,
    DefaultIdentityValues,
    DisplayableIdentity,
    IdentityCertificate,
    IdentityClientConfig,
    IdentityQuery,
    IdentityResolutionResult,
    KnownCertificateType,
    StaticAvatarUrls,
    // Constants
    DEFAULT_SOCIALCERT_CERTIFIER,
};
```

## Key Types

### KnownCertificateType

Enum representing the 9 known certificate types in the BSV ecosystem:

| Variant | Type ID (Base64) | Key Fields |
|---------|------------------|------------|
| `IdentiCert` | `z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=` | firstName, lastName, profilePhoto |
| `DiscordCert` | `2TgqRC35B1zehGmB21xveZNc7i5iqHc0uxMb+1NMPW4=` | userName, profilePhoto |
| `PhoneCert` | `mffUklUzxbHr65xLohn0hRL0Tq2GjW1GYF/OPfzqJ6A=` | phoneNumber |
| `XCert` | `vdDWvftf1H+5+ZprUw123kjHlywH+v20aPQTuXgMpNc=` | userName, profilePhoto |
| `Registrant` | `YoPsbfR6YQczjzPdHCoGC7nJsOdPQR50+SYqcWpJ0y0=` | name, icon |
| `EmailCert` | `exOl3KM0dIJ04EW5pZgbZmPag6MdJXd3/a1enmUU/BA=` | email |
| `Anyone` | `mfkOMfLDQmrr3SBxBQ5WeE+6Hy3VJRFq6w4A5Ljtlis=` | (none) |
| `SelfCert` | `Hkge6X5JRxt1cWXtHLCrSTg6dCVTxjQJJ48iOYd7n3g=` | (none) |
| `CoolCert` | `AGfk/WrT1eBDXpz3mcw386Zww2HmqcIn3uY6x4Af1eo=` | cool (boolean) |

```rust
use bsv_rs::identity::KnownCertificateType;

// Get type ID for a certificate type
let type_id = KnownCertificateType::XCert.type_id();

// Get human-readable name
let name = KnownCertificateType::XCert.name(); // "XCert"

// Parse type ID back to enum
let cert_type = KnownCertificateType::from_type_id(type_id);

// Get all known types
let all_types = KnownCertificateType::all();
```

### DisplayableIdentity

User-friendly representation of an identity for UI display:

```rust
use bsv_rs::identity::DisplayableIdentity;

let identity = DisplayableIdentity {
    name: "Alice".to_string(),
    avatar_url: "https://example.com/avatar.png".to_string(),
    identity_key: "02abc123...".to_string(),
    abbreviated_key: "02abc1...23".to_string(),
    badge_icon_url: "https://socialcert.net/icon.png".to_string(),
    badge_label: "X account certified by SocialCert".to_string(),
    badge_click_url: "https://socialcert.net".to_string(),
};

// Create from just an identity key (uses default values)
let identity = DisplayableIdentity::from_key("02abc123...");

// Create unknown/default identity
let unknown = DisplayableIdentity::unknown();
```

### Contact

Stored contact with identity information and metadata; the three badge fields since #552 and the stored `abbreviated_key` since #559 (the reference record's, kept through read and write). Closed since #552's fold (the keeper's word of 2026-10-31 13:1xZ): `#[non_exhaustive]`, no `Default`; build with `Contact::new(name, identity_key)` and the `with_` setters, read or assign the `pub` fields. `new` judges nothing; `add_contact` refuses an empty name or a non-canonical key in the reference's words, as `saveContact` does. A struct literal outside the crate does not compile (the `compile_fail` doc test on `Contact`; `tests/identity_contact_shape_552.rs`):

```rust
use bsv_rs::identity::{Contact, DisplayableIdentity};

let contact = Contact::new("Alice", "02abc123...")
    .with_avatar_url("https://example.com/avatar.png")
    .with_added_at(1706400000000) // Unix timestamp in milliseconds
    .with_notes("Met at conference")
    .with_tags(["friends", "work"])
    .with_badge_label("Met in person"); // also with_metadata, with_badge_icon_url, with_badge_click_url

// Convert between Contact and DisplayableIdentity: the badges (#558) and the
// abbreviated key (#568) carried both ways
let display = contact.to_displayable_identity();
let contact = Contact::from_identity(display);
```

### IdentityQuery

Query parameters for identity resolution with builder pattern:

```rust
use bsv_rs::identity::IdentityQuery;
use indexmap::IndexMap; // insertion order, the reference's `Record` (#394)

// Query by identity key
let query = IdentityQuery::by_identity_key("02abc123...");

// Query by single attribute
let query = IdentityQuery::by_attribute("email", "user@example.com");

// Query by multiple attributes
let mut attrs = IndexMap::new();
attrs.insert("email".to_string(), "user@example.com".to_string());
let query = IdentityQuery::by_attributes(attrs);

// Builder pattern for complex queries
let query = IdentityQuery::by_attribute("email", "user@example.com")
    .with_certifier("02cf6cdf...")
    .with_limit(10)
    .with_offset(5);
```

### IdentityCertificate

Enriched certificate with decrypted fields and certifier information:

```rust
pub struct IdentityCertificate {
    pub certificate: VerifiableCertificate,
    pub certifier_info: CertifierInfo,
    pub publicly_revealed_keyring: IndexMap<String, String>, // base64 text (#268); the token's order (#394)
    pub decrypted_fields: IndexMap<String, String>,          // the keyring's order (#394)
}

// Access methods
let type_id = cert.type_base64();
let subject = cert.subject_hex();
let certifier = cert.certifier_hex();
let known_type = cert.known_type(); // Option<KnownCertificateType>
```

**Reading a published certificate** (#261): the parsers read the JSON the
reference's `publiclyRevealAttributes` publishes (`{...certificate, keyring}`,
`ts-stack@edf6e03` `IdentityClient.ts:503`). Each field is held as its base64
text, never decoded, as BRC-52 signs it (`brcs@5119a9b`
`peer-to-peer/0052.md:41,97`); the signature is hex, as the reference's
`WalletCertificate.signature` and this crate's `publicly_reveal_attributes`
write it, and one that is not skips its output, never the resolution
(`IdentityClient.ts:823-825`); the keyring's values are held as their base64
text (#268), decoded only where the anyone wallet decrypts; a `revocationOutpoint`
of the txid alone, the reference's default issuance's, reads as index 0
(`revocation_outpoint_from_str`, #268). `decrypted_fields` comes from
`VerifiableCertificate::decrypt_fields` with `ProtoWallet::anyone()`: each
field's text is decoded and decrypted there and nowhere earlier.

### CertifierInfo

Information about a certificate certifier:

```rust
pub struct CertifierInfo {
    pub name: String,
    pub icon_url: String,
    pub description: String,
    pub trust: u8,  // Trust level 0-10
}
```

## IdentityClient

Main client for identity operations. Generic over wallet implementation:

```rust
use bsv_rs::identity::{IdentityClient, IdentityClientConfig};
use bsv_rs::wallet::ProtoWallet;
use bsv_rs::PrivateKey;

// Create a wallet
let private_key = PrivateKey::random();
let wallet = ProtoWallet::new(Some(private_key));

// Create client with default config
let client = IdentityClient::new(wallet.clone(), IdentityClientConfig::default());

// Create client with custom config
let config = IdentityClientConfig::with_originator("myapp.example.com")
    .with_network(NetworkPreset::Mainnet)
    .with_token_amount(5);
let client = IdentityClient::new(wallet, config);

// Create with custom resolver
let client = IdentityClient::with_resolver(wallet, config, custom_resolver);
```

### Public Revelation Methods

```rust
// Publicly reveal certificate attributes
let result = client.publicly_reveal_attributes(
    certificate,
    vec!["userName".to_string(), "profilePhoto".to_string()]
).await?;

match result {
    BroadcastResult::Success(s) => println!("TXID: {}", s.txid),
    BroadcastResult::Failure(f) => println!("Failed: {}", f.description),
}
// A certificate whose signature does not verify, or a name it does not
// carry, is refused before the wallet is called (`reveal.rs`, #307)
// The token is the subject's signed PushDrop, the reference's bytes; a
// createAction with no transaction is `Err(IdentityError("Public reveal
// failed: failed to create action!"))`, a refused broadcast a `Failure` (#310)

// Simplified version returning just txid
let txid = client.publicly_reveal_attributes_simple(certificate, fields).await?;

// Revoke a previous revelation by spending the identity token: the lookup's
// outputs authenticated, each matching one spent at its index, the action
// aborted on a failure, a double spend retried (`revoke.rs`, #327)
client.revoke_certificate_revelation(serial_number_base64).await?;
```

### Resolution Methods

```rust
// Resolve by identity key (second param enables contact override): every
// output of the lookup answer read in order, every admitted identity of the
// asked subject returned, the most trusted certifier's ahead, ties in the
// answer's order (#737, the list)
let identities = client.resolve_by_identity_key("02abc123...", true).await?;
if let Some(id) = identities.first() {
    println!("Found: {} ({})", id.name, id.abbreviated_key);
}

// Resolve by attributes (second param enables contact override); the
// lookup body keeps the attributes' insertion order (#394)
let mut attrs = IndexMap::new();
attrs.insert("email".to_string(), "user@example.com".to_string());
let identities = client.resolve_by_attributes(attrs, true).await?;

// Discover all certificates for an identity (the asked subject's alone, #739)
let certs = client.discover_certificates("02abc123...").await?;

// Discover specific certificate type: only certificates of the asked type
// are returned, whatever the host answers (#744)
let x_certs = client.discover_certificates_by_type(
    "02abc123...",
    KnownCertificateType::XCert.type_id()
).await?;

// Complex query returning IdentityResolutionResult: only the certificates
// matching the subject, type and certifier the question carries (#746)
let query = IdentityQuery::by_identity_key("02abc123...").with_limit(10);
let results = client.query(query).await?;
for result in results {
    println!("{}: {} certs", result.identity.name, result.certificates.len());
}
```

### Contact Management via Client

```rust
// Get all contacts (pass true to force refresh from storage)
let contacts = client.get_contacts(false).await?;

// Get specific contact
if let Some(contact) = client.get_contact("02abc123...").await? {
    println!("Contact: {}", contact.name);
}

// Save a contact (with optional metadata)
let identity = DisplayableIdentity::from_key("02abc123...");
client.save_contact(identity, Some(serde_json::json!({"source": "import"}))).await?;

// Remove a contact
client.remove_contact("02abc123...").await?;
```

### Utility Methods

```rust
// Get the wallet's identity key
let my_key = client.get_identity_key().await?;

// Parse an identity certificate into displayable format (static method)
let displayable = IdentityClient::<ProtoWallet>::parse_identity(&cert);
```

## ContactsManager

Direct contact management with encrypted storage, search, and caching:

```rust
use bsv_rs::identity::{ContactsManager, ContactsManagerConfig, Contact};

let config = ContactsManagerConfig::with_originator("myapp.example.com");
let manager = ContactsManager::new(wallet, config);

// CRUD operations
manager.add_contact(contact).await?;
let contact = manager.get_contact("02abc123...").await?;
manager.update_contact("02abc123...", updated_contact).await?;
manager.remove_contact("02abc123...").await?;

// List and search
let all = manager.list_contacts().await?;
let refreshed = manager.list_contacts_with_refresh(true).await?;
let results = manager.search_contacts("alice").await?;  // Searches name, tags, notes
let tagged = manager.get_contacts_by_tag("friends").await?;

// Cache management
manager.clear_cache().await;
let is_init = manager.is_cache_initialized().await;
let count = manager.cached_count().await;
```

### Storage Model

Contacts are stored as encrypted PushDrop tokens in the wallet's basket system (since #544 the reference's: the record `validateContact` admits, encrypted, then the wallet's signature over the ciphertext as the token's second field; `added_at` is not in the token, the manager's cache holds it):
- Each contact is encrypted with a per-contact key
- Tagged with HMAC-hashed identity key for privacy-preserving lookup
- Stored in the "contacts" basket
- Custom instructions store the key ID for decryption

## Configuration Types

### IdentityClientConfig

```rust
pub struct IdentityClientConfig {
    pub network_preset: NetworkPreset,  // Mainnet or Testnet
    pub protocol_id: (u8, String),      // Default: (1, "identity")
    pub key_id: String,                 // Default: "1"
    pub token_amount: u64,              // Satoshis for revelation outputs (default: 1)
    pub output_index: u32,              // Output index for identity token (default: 0)
    pub originator: Option<String>,     // Application originator; None: none to the wallet (#318, #329)
}

// Builder methods
let config = IdentityClientConfig::with_originator("myapp.com")
    .with_network(NetworkPreset::Testnet)
    .with_token_amount(100);
```

### ContactsManagerConfig

```rust
pub struct ContactsManagerConfig {
    pub protocol_id: (u8, String),  // Default: (2, "contact"), the reference's; every contact key derives under it (#542)
    pub basket: String,             // Default: "contacts"
    pub originator: Option<String>, // Application originator; None: none to the wallet (#329)
}

let config = ContactsManagerConfig::with_originator("myapp.com");
```

## Broadcast Result Types

```rust
pub enum BroadcastResult {
    Success(BroadcastSuccess),
    Failure(BroadcastFailure),
}

pub struct BroadcastSuccess {
    pub txid: String,
    pub message: Option<String>,
}

pub struct BroadcastFailure {
    pub code: String,
    pub description: String,
}

// Helper methods
result.is_success();
result.txid();  // Option<&str>
result.into_result();  // Result<BroadcastSuccess, BroadcastFailure>
```

## Constants

| Constant | Value |
|----------|-------|
| `DEFAULT_SOCIALCERT_CERTIFIER` | `02cf6cdf466951d8dfc9e7c9367511d0007ed6fba35ed42d425cc412fd6cfd4a17` |

### StaticAvatarUrls

UHRP hashes for certificate type avatars:

```rust
use bsv_rs::identity::StaticAvatarUrls;

StaticAvatarUrls::EMAIL;   // Envelope icon
StaticAvatarUrls::PHONE;   // Phone icon
StaticAvatarUrls::ANYONE;  // Anyone certificate avatar
StaticAvatarUrls::SELF;    // Self certificate avatar
```

### DefaultIdentityValues

Constants for unverified/unknown identities:

```rust
use bsv_rs::identity::DefaultIdentityValues;

DefaultIdentityValues::NAME;           // "Unknown Identity"
DefaultIdentityValues::AVATAR_URL;     // UHRP hash for default avatar
DefaultIdentityValues::BADGE_ICON_URL; // UHRP hash for default badge icon
DefaultIdentityValues::BADGE_LABEL;    // "Not verified by anyone you trust."
DefaultIdentityValues::BADGE_CLICK_URL; // Documentation link
```

## Error Handling

The module uses error variants from `crate::Error`:

```rust
// General identity error
Error::IdentityError(String)

// Contact not found
Error::ContactNotFound(String)
```

## Overlay Network Integration

The identity module uses the overlay network for discovery and broadcast:

| Service | Purpose |
|---------|---------|
| `ls_identity` | Lookup service for identity queries |
| `tm_identity` | Topic for broadcasting identity revelations |

Queries are performed via `LookupResolver`, broadcasts via `TopicBroadcaster`.

## Wire Format Compatibility

JSON serialization uses camelCase field names for cross-SDK compatibility:

```rust
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisplayableIdentity {
    pub name: String,
    pub avatar_url: String,      // serializes as "avatarUrl"
    pub identity_key: String,    // serializes as "identityKey"
    // ...
}
```

## Cross-SDK Compatibility

Since #454 contact update/removal and revelation revocation call the shared
`wallet::pushdrop::sign`: `data: SHA256(preimage)`, exactly the request shape
of `ts-stack@edf6e03` `PushDrop.ts:234-258`, preserving the resulting signature.
The Node 22 #326, #318 and #327 recorders pin signature-request JSON; the contact
shape checks, #318 request comparison, #327 request/transaction comparisons and
`identity_spend_witness` pin it. The helper extraction keeps existing public
method paths. No identity API migration is required.

This module maintains API compatibility with:
- [TypeScript SDK identity](https://github.com/bitcoin-sv/ts-sdk) - `IdentityClient`, `ContactsManager`
- [Go SDK identity](https://github.com/bitcoin-sv/go-sdk) - `identity.Client`

Key compatibility points:
- Same certificate type IDs (base64-encoded SHA-256 hashes)
- Same default certifier public key
- Same overlay service/topic names
- Compatible JSON serialization format with camelCase

## Related Documentation

- `../auth/CLAUDE.md` - Authentication module with certificate types
- `../overlay/CLAUDE.md` - Overlay network module for resolution queries
- `../wallet/CLAUDE.md` - Wallet module for key operations
- `../../CLAUDE.md` - Project root documentation
