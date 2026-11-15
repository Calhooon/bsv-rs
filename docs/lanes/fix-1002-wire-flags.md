# Lane fix-1002-wire-flags (#1002): the wallet wire's flag bytes beside the reference's

Started from `d892e206` (`origin/beta`'s tip on 2026-11-15). The issue carries no comment: no decision and no wait were recorded on it.

## What was read

- The reference at the pin, whole: `packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts` (2,036 lines, **T** below) and `WalletWireProcessor.ts` (2,583 lines, **P** below) at `ts-stack@edf6e03`.
- The reference's head, `ts-stack@3b1abc56` (2026-11-13): `labelQueryMode`, `tagQueryMode` and `include` carry the pin's assignments (`WalletWireTransceiver.ts:433-434,711-712`, `WalletWireProcessor.ts:846-855,1221-1225`). The head adds a `spendable` extension to listOutputs (a trailing request byte and a byte per output), which the pin does not have and this lane does not port (the drift census of 2026-11-12 lists it).
- The older reference, `ts-sdk@9e3ede6b`: the same three assignments (`WalletWireTransceiver.ts:548-551,932-941`).
- go-sdk at `2ca481c` and at `57b9cb61` (`origin/master` of the local clone), by reading: `wallet/serializer/list_actions.go:12-15,24-33` writes `labelQueryMode` 1 for `any` and 2 for `all`; `list_outputs.go:11-15,26-40` writes `tagQueryMode` 1 `all`, 2 `any` and `include` 1 and 2; `util/writer.go:212-221` writes an absent string list as nine `0xFF`; the presence flags of an action result and the two booleans of a listed action are written 0 or 1 (`create_action_result.go:19-20`, `util/writer.go:169-201,223-233`, `list_actions.go:145,183`).
- This crate's wire, whole: `src/wallet/wire/{transceiver,processor,requests,results,encoding,reader,bounds,mod,linkage,discovery}.rs`.

## The instance

`WalletWireTransceiver::list_actions` wrote `labelQueryMode` through `WireWriter::write_optional_query_mode`, which wrote -1 absent, 0 `any`, 1 `all`; the reference writes and reads -1, 1 `any`, 2 `all` (T:357-360, P:830-841), and go-sdk the same. Recorded from the reference (`crate_base_rows`): the frame this crate wrote for `any` is refused by the reference's processor (`Invalid labelQueryMode flag: expected -1, 1, or 2, received 0`, code 1, its wallet not called), and the frame it wrote for `all` is read there as `any`. The byte has been wrong since the writer was added (`242afd59`, 2026-01-26): every tagged release carries it, from `v0.3.1` (the oldest tag) to `v0.8.9` and `v0.9.0-beta.7`.

The reader of the byte in this crate is the public `WireReader::read_optional_query_mode` alone: the processor answers listActions `listActions requires a full wallet implementation` and reads none of its parameters. Both are conformed. No local clone of a dependent reads or writes the byte through these helpers (`bsv-wallet-toolbox-rs` at `2cacee87` and `bsv-wallet-cli` at `006b0912` were searched by path; the toolbox uses the transceiver in tests alone).

## The recorder

`tests/support/wire_flags_1002.mjs`, the bundle of `packages/sdk` at `edf6e03` (bun 1.3.11) under Node v22.18.0, two runs byte-identical, writes `tests/vectors/wallet_wire/flags_1002.json` (sha256 `3df2208f...8d98`):

| Group | Rows | What it holds |
|---|---:|---|
| `request_rows` | 61 | the reference transceiver's request frame for one set of args, and the args the reference processor's wallet was given (its reading) |
| `request_flag_rows` | 29 | for ten groups of request rows that differ in one argument: the offset and the byte that moved, found by comparing the frames |
| `crate_base_rows` | 3 | this crate's listActions frames before #1002 (`d892e206`), served to the reference's processor |
| `processor_refusal_rows` | 26 | a recorded request with one flag byte set out of range, served to the reference's processor: its error frame |
| `response_rows` | 33 | the reference processor's result frame for an answer its wallet gave, and the value the reference's transceiver read |
| `response_flag_rows` | 16 | for five groups of response rows: the offset and the byte that moved |
| `transceiver_refusal_rows` | 28 | a recorded response with one flag byte out of range or its length changed, served to the reference's transceiver: its words |

Every byte and every verdict is the reference's, save the frames marked as built in the recorder's header (a recorded frame with one byte replaced) and `crate_base_rows`' request bytes. The two members named `senderIdentityKey` and `identityKey` carry the generator point, the one key literal `.gitleaks.toml` already lets through for such a member; the scan's `generic-api-key` rule reads a member of that name by its value, and a lane adds no allowlist.

## The table

**T** and **P** are the reference's two files at `ts-stack@edf6e03`. `tx` is `src/wallet/wire/transceiver.rs`, `enc` `encoding.rs`, `req` `requests.rs`, `proc` `processor.rs`, `fl` `flags.rs`, `bnd` `bounds.rs`, `lnk` `linkage.rs`, `dsc` `discovery.rs`, `res` `results.rs`, `mod` `mod.rs`, each at this lane's tip. "stub" is one of the twelve calls this crate's processor answers `<call> requires a full wallet implementation` (`proc`), reading no parameter and writing no result: for those the result's writer is the public `WireWriter` helper a wallet host would call. "recorded" names the rows of the vector that hold the cell. An optional boolean is one signed byte, -1 absent, 0, 1; an optional varint is the value, or nine `0xFF` (-1) when absent.

### Parameters

| Method | Field | Bytes | This crate's writer | This crate's reader | T (writer) | P (reader) | Verdict |
|---|---|---|---|---|---|---|---|
| every call | call code, originator length | `u8`, `u8` | `tx:119-122` | `proc`, `originator.rs` | T:98-99 | P:276-294 | equal (#338, #914) |
| createAction | `inputBEEF` | length or -1 | `tx:472` | stub | T:184-189 | P:311-316 | equal absent and present (recorded: `createAction_input_unlocking_length`, `_script`, and eight rows without); a present empty value: stated row S2 |
| createAction | `inputs`, `outputs` | count or -1 | `tx:475-498`, `tx:501-525` | stub | T:192-209 | P:320-427 | equal (recorded) |
| createAction | input `unlockingScript` | length, or -1 then `unlockingScriptLength` | `tx:482-488` | stub | T:1253-1260 | P:331-339 | equal in both forms (recorded: `createAction_input_unlocking_length`, `createAction_input_unlocking_script`) |
| createAction | input `sequenceNumber`, `lockTime`, `version` | optional varint | `tx:494`, `tx:528`, `tx:531` | stub | T:1263, T:212-213 | P:347-352, P:431-444 | equal (recorded: `createAction_options_all`, `createAction_input_unlocking_script`) |
| createAction | output `basket`, `customInstructions` | length or -1 (empty written -1) | `tx:515`, `tx:518` | stub | T:1283-1284, T:1180-1188 | P:385-400 | equal (recorded: `createAction_input_unlocking_script` present, `_length` absent) |
| createAction | output `tags`, `labels` | count or -1 | `tx:521`, `tx:534` | stub | T:1285, T:216 | P:403-419, P:447-459 | equal (recorded: `labels: []`) |
| createAction | options present | `i8` 0, 1 | `tx:538`, `tx:585` | stub | T:1305-1309 | P:463 | equal (recorded: `createAction_options_absent`, `_all`) |
| createAction | `signAndProcess`, `acceptDelayedBroadcast`, `returnTXIDOnly`, `noSend`, `randomizeOutputs` | optional boolean | `tx:540-541`, `tx:560-561`, `tx:583` | stub | T:1310-1311, T:1314-1315, T:1325 | P:469-478, P:515-521, P:565-568 | equal (recorded: group `createAction signAndProcess`, `_options_all`) |
| createAction | `trustSelf` | `i8` 1 `known`, -1 | `tx:544-548` | stub | T:1312 | P:481-490 | equal (recorded: group `createAction trustSelf`) |
| createAction | `knownTxids`, `noSendChange`, `sendWith` | count or -1 | `tx:551-558`, `tx:564-581` | stub | T:1313, T:1316-1324 | P:495-512, P:526-561 | equal (recorded) |
| signAction | spend `sequenceNumber` | optional varint | `enc:1016` | stub (`enc:360`) | T:290 | P:671-676 | equal (recorded: `signAction_options_all`) |
| signAction | options present | `i8` 0, 1 | `tx:666`, `tx:680` | stub | T:1340-1344 | P:689 | equal (recorded) |
| signAction | `acceptDelayedBroadcast`, `returnTXIDOnly`, `noSend`; `sendWith` | optional boolean; count or -1 | `tx:667-678` | stub | T:1345-1348 | P:695-728 | equal (recorded) |
| abortAction | none | | `tx:704` | `proc` | T:323-342 | P:782-811 | no flag |
| listActions | `labels` | count (no -1) | `tx:738` | stub | T:352 | P:818-828 | equal (recorded) |
| listActions | **`labelQueryMode`** | `i8` -1, 1 `any`, 2 `all` | `tx:741`, `enc:940` | stub; `enc:255`, `fl:50` | T:357-360 | P:830-841 | **fixed here**: 0 and 1 until #1002 (recorded: group `listActions labelQueryMode`, `crate_base_rows`, three refusals) |
| listActions | six `include…` booleans, `seekPermission` | optional boolean | `tx:744-749`, `tx:756` | stub | T:363-372, T:376 | P:845-855, P:874 | equal (recorded: groups `listActions includeLabels`, `listActions seekPermission`) |
| listActions | `limit`, `offset` | optional varint | `tx:752-753` | stub | T:374-375 | P:858-871 | equal (recorded: `listActions_limit_offset`) |
| internalizeAction | output `protocol` | `u8` 1 `wallet payment`, 2 `basket insertion` | `tx:786`, `tx:802` | stub | T:592, T:601 | P:1085-1141 | equal (recorded: `internalizeAction_both_protocols`) |
| internalizeAction | insertion `customInstructions`; `tags` | length or -1; count, 0 when absent | `tx:805-807` | stub (`bnd:92`) | T:605-616 | P:1113-1136 | equal (recorded) |
| internalizeAction | `labels`; `seekPermission` | count or -1; optional boolean | `tx:813`, `tx:819` | stub | T:569, T:573 | P:1147-1165 | equal (recorded) |
| listOutputs | `tags` | count, 0 when absent | `tx:845-846` | stub | T:628-635 | P:1192-1203 | equal (recorded) |
| listOutputs | `tagQueryMode` | `i8` -1, 1 `all`, 2 `any` | `tx:849-855` | stub | T:636-638 | P:1206-1217 | equal (recorded: group `listOutputs tagQueryMode`; `listOutputs-simple-args.json`); no helper of `enc` writes it |
| listOutputs | `include` | `i8` -1, 1 `locking scripts`, 2 `entire transactions` | `tx:858-864` | stub | T:639-641 | P:1220-1231 | equal (recorded: group `listOutputs include`); no helper of `enc` writes it |
| listOutputs | `includeCustomInstructions`, `includeTags`, `includeLabels`, `seekPermission` | optional boolean | `tx:866-868`, `tx:872` | stub | T:642-644, T:647 | P:1236-1245, P:1264 | equal (recorded: group `listOutputs includeTags`) |
| listOutputs | `limit`; `offset` | optional varint | `tx:870-871` | stub | T:645-646 | P:1248-1261 | equal (recorded: `listOutputs_limit_offset`); an `offset` below -1 refused at this crate's writer (the root list's #149 row) |
| relinquishOutput | none | | `tx:884` | stub | T:702-715 | P:1358-1384 | no flag |
| getPublicKey | `identityKey` | `u8` 0, 1 | `tx:169` | `req:199` | T:757 | P:1391 | equal (recorded: `getPublicKey_identityKey`; refusals 2 and 255 byte for byte) |
| getPublicKey | `forSelf`, `seekPermission` | optional boolean | `tx:186`, `tx:188` | `req:213`, `req:215` | T:772-780 | P:1399-1403 | bytes equal (recorded: group `getPublicKey forSelf`); **fixed here**: a byte outside -1, 0, 1 was refused in this crate's words, now the reference's frame |
| the seven key calls, the two linkage calls | protocol security level | `u8` 0, 1, 2 | `enc:876` | `enc:178` | T:1359 | P:2439-2448 | equal (#216) |
| the same | counterparty | `u8` 0 absent, 11 `self`, 12 `anyone`, or 33 bytes | `enc:866` | `enc:154` | T:1366-1374 | P:2450-2463 | equal (recorded: `encrypt_counterparty_self`, `_anyone`, `_key`; #550) |
| the same, getPublicKey for the identity key | `privileged` | optional boolean | `mod:582` | `req:75` | T:1450-1454 | P:2469 | bytes equal (recorded: group `getPublicKey privileged`); **fixed here**: the refusal's words |
| the same | `privilegedReason` length | `i8`, -1 absent, 0 to 127 | `mod:582` (past 127 refused before a byte) | `req:77`, `fl:35` | T:1455-1461 | P:2470, P:54-61 | bytes equal (recorded); **fixed here**: the refusal's words for a negative length |
| encrypt, decrypt, createHmac, verifyHmac | `seekPermission` | optional boolean | `tx:219`, `tx:248`, `tx:277`, `tx:312` | `req:228`, `req:258` | T:952, T:986, T:1018, T:1052 | P:1430, P:1457, P:1484, P:1512 | bytes equal (recorded: one row a call); **fixed here**: the refusal's words |
| createSignature, verifySignature | data type | `u8` 1 data, 2 hash | `mod:552` | `req:181` | T:1082-1090, T:1137-1144 | P:1533-1543, P:1576-1586 | equal (recorded: four rows; refusal 3 byte for byte; #199) |
| createSignature, verifySignature | `seekPermission`; verifySignature `forSelf` | optional boolean | `tx:345`, `tx:387`; `tx:371` | `req:270`, `req:293`; `req:290` | T:1092, T:1146; T:1130-1134 | P:1546, P:1589; P:1569 | bytes equal (recorded); **fixed here**: the refusal's words (`verifySignature forSelf = 2`) |
| revealCounterpartyKeyLinkage, revealSpecificKeyLinkage | privileged pair | as above | `lnk:120`, `lnk:171` | `req:116`, `req:137` | T:809, T:874-882 | P:1739, P:1793 | equal (recorded: three rows; #406) |
| acquireCertificate | privileged pair | as above | `tx:926-933` | stub | T:1402 | P:1886 | equal on the recorded frames (absent, and `false`) |
| acquireCertificate | `acquisitionProtocol` | `u8` 1 `direct`, 2 `issuance` | `tx:936-939` | stub | T:1403 | P:1889-1898 | equal (recorded: two rows) |
| acquireCertificate | `keyringRevealer` | `u8` 11 `certifier`, or 33 bytes | `tx:976-986` | stub | T:1412-1414 | P:1914-1923 | equal (recorded: `certifier`) |
| listCertificates | `limit`, `offset` | optional varint | `tx:1052-1053` | stub | T:1488-1497 | P:2018-2030 | equal (recorded: two rows) |
| listCertificates | privileged pair | as above | `tx:1056-1063` | stub | T:1498 | P:2032 | equal on the recorded frames (absent, and `true` with a reason of 8 bytes) |
| proveCertificate | privileged pair | as above | `tx:1169-1176` | stub | T:1600 | P:2188 | equal on the recorded frames (absent, and `true` with a reason of 8 bytes) |
| relinquishCertificate | none | | `tx:1195` | stub | T:1627-1650 | P:2227-2257 | no flag |
| discoverByIdentityKey, discoverByAttributes | `limit`, `offset`; `seekPermission` | optional varint; optional boolean | `dsc:26-28`, `dsc:57-59` | stub | T:1779-1790, T:1825-1836 | P:2268-2283, P:2331-2346 | equal (recorded: two rows) |
| getHeaderForHeight | `height` | varint, 1 to 2^32 - 1 | `tx:1237` | `validation.rs` | T:1893-1897 | P:1671-1676 | equal (#216) |
| isAuthenticated, waitForAuthentication, getHeight, getNetwork, getVersion | none | | `tx` | `proc` | T:1849-1934 | P:1605-1732 | no parameter |

### Results

| Method | Field | Bytes | This crate's writer | This crate's reader | T (reader) | P (writer) | Verdict |
|---|---|---|---|---|---|---|---|
| createAction | `txid` present, `tx` present | `i8` 0, 1 | stub | `tx:596`, `fl:64` | T:238-244 | P:588-603 | **fixed here**: a byte other than 1 was read as absent; now 0 or 1, another byte refused in the reference's words (recorded: `createAction_txid`, `_txid_tx`, four refusals) |
| createAction | `noSendChange` | count or -1 | stub | `tx:599-613` | T:246-258 | P:608-615 | equal (#473) |
| createAction, signAction | `sendWithResults`; entry status | count or -1; `i8` 1 `unproven`, 2 `sending`, 3 `failed` | `enc:999`, `enc:980` | `enc:346`, `enc:324` | T:1217-1238 | P:618-626, P:769-777, P:151-156 | equal (#590) |
| createAction | `signableTransaction` present | `i8` 0, 1 | stub | `tx:619` | T:263 | P:631-644 | **fixed here**, as the two above (recorded: `createAction_signable`, two refusals) |
| signAction | `txid` present, `tx` present | `i8` 0, 1 | stub | `tx:691`, `fl:64` | T:310-315 | P:749-764 | **fixed here** (recorded: `signAction_txid`, four refusals) |
| listActions | `status` | `i8` 1 to 8 | `enc:1197`, `enc:895` | `enc:596`, `fl:83` | T:395-399, T:422 | P:909, P:158-168 | **fixed here**: -1 was read as `unprocessed` and another code refused in this crate's words; now 1 to 8, another byte `Unknown status code: N` (recorded: group `listActions status`, three refusals) |
| listActions | `isOutgoing` | `i8` 0, 1 | `enc:1198` | `enc:597` | T:423 | P:912 | **fixed here**: -1 was read as `false`; now 0 or 1 (recorded: group `listActions isOutgoing`, two refusals) |
| listActions | `labels` | count or -1 | `enc:1200` | `enc:599`, `bnd:81` | T:428-435 | P:922-931 | **fixed here**: an absent list was written as a count of 0 and an empty list read as absent; now -1 absent, a count otherwise, on both sides (recorded: `listActions_labels_absent`, `_empty`, `_one`; go-sdk's `listActions-simple-result.json` carries the nine `0xFF`) |
| listActions | `inputs`, `outputs` | count or -1 | `enc:1208-1224` | `enc:605-631` | T:450-466 | P:942-990 | equal (recorded: `listActions_inputs_outputs_empty`) |
| listActions | input `sourceLockingScript`, `unlockingScript` | length or -1 | `enc:1166-1167` | `enc:543-544` | T:486-489 | P:954-972 | equal absent and non-empty (recorded: `listActions_input_scripts_absent`); a present empty script: stated row S2 |
| listActions | output `lockingScript`, `customInstructions` | length or -1 | `enc:1180`, `enc:1185` | `enc:566`, `enc:571` | T:529-530, T:543-544 | P:999-1005, P:1041-1050 | read equal (recorded); written: a present empty value, stated row S2 |
| listActions | output `spendable` | `i8` 0, 1 | `enc:1181` | `enc:567` | T:531 | P:1008 | **fixed here**: -1 was read as `false` (recorded: group `listActions output spendable`, two refusals) |
| listActions | output `basket`, `tags` | length or -1; count or -1 | `enc:1183-1184` | `enc:569-570` | T:533-542 | P:1020-1038 | read equal (the reference's reader answers `tags: []` for -1, its validator requires `basket`); written: stated row S1 |
| internalizeAction, relinquishOutput, relinquishCertificate, abortAction, verifyHmac, verifySignature, waitForAuthentication | none | empty | `res` | `tx` | T | P | no flag |
| listOutputs | `BEEF` | length or -1 | `enc:810` | `bnd:145` | T:657-658 | P:1289-1295 | equal (recorded: absent; #487's frames present) |
| listOutputs | output `lockingScript`, `customInstructions` | length or -1 | `enc:1241-1242` | `enc:654-655` | T:677-680 | P:1307-1325 | read equal (recorded: `listOutputs_empty_strings`); written: a present empty value, stated row S2 |
| listOutputs | output `tags`, `labels` | count or -1 | `enc:1243-1244` | `enc:656-657`, `bnd:81` | T:681-698 | P:1328-1351 | **fixed here**, as listActions' `labels` (recorded: `listOutputs_optionals_absent`, `_tags_labels_empty`, `_tags_labels_one`; go-sdk's `listOutputs-simple-result.json`); on the base the recorded `_tags_labels_empty` answer (`includeTags` and `includeLabels` asked, both lists empty) was refused by this crate's client, `Invalid listOutputs result outputs[0].tags: expected the explicitly requested output tags`, the empty list read as no list |
| getPublicKey | none | 33 bytes | `validation.rs` | `tx:196` | T:783-787 | P:1417 | no flag |
| isAuthenticated | `authenticated` | one byte, 0 or 1 | `proc:484` | `tx:406`, `fl:107` | T:1855-1862 | P:1619-1622 | **fixed here**: -1 was read as `false`, a second byte was not refused, an empty result was refused in the reader's words (recorded: group `isAuthenticated`, four refusals) |
| getNetwork | `network` | one byte, 0 `mainnet`, 1 `testnet` | `proc:536` | `tx:434`, `fl:107` | T:1915-1919 | P:1710 | **fixed here**: a second byte was not refused; the two refusals' words (recorded: group `getNetwork`, four refusals) |
| revealSpecificKeyLinkage | security level; `proofType` | `u8` 0, 1, 2; `u8` | `res:143`, `res:146` | `lnk:83`, `lnk:195` | T:899, T:908 | P:1821, P:1842 | equal (#406) |
| listCertificates | `keyring` present | `i8` 0, 1 | stub | `tx:1087`, `mod:253` | T:1514 | P:2073-2094 | equal (recorded: two rows, two refusals; #183); the reference's reader answers an empty keyring for 0 where this crate's type answers `None` |
| listCertificates | `verifier` | length 0, or 33 and the key | stub | `tx:1098-1106` | T:1533-1542 | P:2096-2102 | bytes equal (recorded); **fixed here**: the refusal's capital (`Invalid listCertificates verifier length: ...`) |
| discoverByIdentityKey, discoverByAttributes | `certifierInfo.trust` | `u8` 1 to 10 | `enc:1098` | `enc:433` | T:1710 | P:2520 | equal (#183, #247) |
| listCertificates, the two discovery calls, listActions, listOutputs | total | varint, 0 to 2^32 - 1 | stub | `tx:1073`, `dsc`, `bnd:127`, `bnd:144` | T:380-385, T:651-656, T:1501-1506, T:1676-1681 | P:170-183 | equal (#190, #255, #473) |
| getHeight | `height` | varint, 1 to 2^32 - 1 | `proc` | `bnd:10` | T:1882-1884 | P:1662 | equal (#473) |

### The stated rows (not conformed here)

- **S1. An action output's `tags` and `basket` are not optional in this crate's type** (`WalletActionOutput { tags: Vec<String>, basket: String }`, `src/wallet/types.rs`), so `write_wallet_action_output` writes a count of 0 for a list the reference's processor would write as absent (nine `0xFF`, P:1029-1031) and has no absent `basket` to write (P:1020-1022; the reference's result validator refuses a result without `basket`, recorded while the vector was built). Every reader reads either form; the reference's transceiver answers `tags: []` for both (T:535-542). Conforming is a public shape (`Option`): the captain's question below. Pinned: `an_absent_tag_list_and_an_empty_script_are_written_otherwise_stated_1002`.
- **S2. A present empty value is written as absent** by `write_optional_bytes` and `write_optional_string` (`enc:798-818`): the reference's transceiver does the same for a request's optional string (T:1180-1188, an empty string -1), which is why the helpers do; the reference's processor writes a present empty `lockingScript`, `sourceLockingScript`, `unlockingScript` or `customInstructions` of a result as a length of 0 (P:954-972, P:999-1005, P:1041-1050, P:1307-1325), and its transceiver writes a present empty `inputBEEF` as a length of 0 (T:184-189). The readers on every side read both forms; this crate's reads a length of 0 as `Some` of nothing. Not conformed: the two forms are one type's `Some(empty)` here, the cells are a wallet's answer of an empty script or an empty instruction, and a writer that told them apart would be a second pair of helpers. Pinned by the same test.
- **S3. The words of three reads that are no flag** stay this crate's: a privileged reason that is not UTF-8 (`invalid privilegedReason UTF-8: ...`, `req:81-83`; the reference's `toUTF8Strict` sentence), and the public `read_optional_bool`'s and `read_query_mode`'s own refusals, which name no field.

## The public helpers for modes, and which method uses each

| Helper (`WireReader` / `WireWriter`) | Bytes | Used by | The reference's bytes |
|---|---|---|---|
| `write_optional_query_mode`, `read_optional_query_mode` | -1, 1 `any`, 2 `all` since #1002 | `list_actions` (`tx:741`); no reader in the crate | listActions' `labelQueryMode`: equal |
| `write_optional_bool`, `read_optional_bool` | -1, 0, 1 | 36 sites of `tx`, `dsc`, `proc`, `mod` and the two action writers of `enc`; the reader by `benches/wire_codec/support.rs` and tests | every optional boolean: equal at the six recorded sites |
| `write_action_status`, `read_action_status` | 1 to 8; `None` as -1 | `write_wallet_action` (`enc:1197`, always `Some`) | 1 to 8 equal; -1 is no method's byte |
| `write_send_with_result_status`, `read_send_with_result_status` | 1, 2, 3 | the result array's helpers | equal (#590) |
| `write_query_mode`, `read_query_mode` | `u8` 0 `any`, 1 `all` | no method | no method's bytes: listActions' are 1 and 2, listOutputs' 2 and 1; the reference's processor refuses 0 at both |
| `write_output_include`, `read_output_include` | `u8` 0, 1 | no method | no method's bytes: listOutputs' `include` is 1 and 2, 0 refused |
| `write_optional_output_include`, `read_optional_output_include` | -1, 0, 1 | no method (`list_outputs` writes the three bytes inline, `tx:858-864`) | the absent byte equal; 0 and 1 are no method's |

Seen beside them, the same kind (a public helper no method uses, whose bytes no method of the reference carries): `write_internalize_output` / `read_internalize_output` with `write_optional_wallet_payment` and `write_optional_basket_insertion` (the protocol as a string and two presence bytes, where the method writes a protocol byte 1 or 2 and one remittance, `tx:786-808`), `write_optional_wallet_certificate` / `read_optional_wallet_certificate` (a presence byte no frame carries), `write_optional_protocol_id` / `read_optional_protocol_id` (level 255; no request uses it since #193, as `src/wallet/wire/CLAUDE.md` says), and `status_codes::UNKNOWN` (-1).

Each existing round-trip unit test of `encoding.rs` reads back what the same file wrote; its cell against the recorded byte is in `tests/wallet_wire_flags_1002.rs`:

| Unit test (`src/wallet/wire/encoding.rs`) | Its cell |
|---|---|
| `test_optional_query_mode_roundtrip` | `the_optional_query_mode_helpers_are_the_recorded_label_query_mode_bytes_1002` |
| `test_optional_bool` | `the_optional_bool_helpers_are_the_recorded_optional_boolean_bytes_1002` |
| `test_action_status_roundtrip` | `the_action_status_helpers_are_the_recorded_status_bytes_1002` |
| `test_query_mode_roundtrip`, `test_output_include_roundtrip`, `test_optional_output_include_roundtrip` | `the_unused_mode_helpers_write_no_methods_bytes_stated_1002` (their bytes beside the recorded bytes of the fields their names suggest, the difference asserted) |

## Questions for the captain

1. **The helpers no method uses** (the last three rows of the table above and the four seen beside them). Remove them at the cut, or make their bytes a method's (`write_optional_output_include` as listOutputs' 1 and 2, with `list_outputs` calling it; a `tagQueryMode` writer of its own)? Nothing is removed and no byte of theirs is changed here. Migration if removed: a caller writes the method's bytes through the transceiver, or the byte itself with `write_i8`.
2. **`WalletActionOutput.tags` and `.basket` as `Option`** (S1), so an absent list and an absent basket can be written as the reference's processor writes them. A public shape: not built here. Migration: `tags: Some(vec)` for `tags: vec`, `basket: Some(name)` for `basket: name`; a reader's `output.tags` becomes `output.tags.unwrap_or_default()`.
3. **`read_action_status`'s `None` for -1 and `status_codes::UNKNOWN`**: no method carries the byte and listActions' reader now refuses it. Keep the pair for a caller's own frames, or remove at the cut?

## RED

On a scratch copy of `d892e206` (`git archive` under the lane's out folder, the test file and the vector overlaid, `CARGO_TARGET_DIR=/Volumes/Lanes/targets/fix-1002-wire-flags-red`), `cargo test --features "full,http" --test wallet_wire_flags_1002`: **16 of 19 RED**, each at the earliest cell that differs:

| Test | On the base |
|---|---|
| `list_actions_writes_label_query_mode_as_the_reference_does_1002` | `left: "04000105616c70686100ff..."`, `right: "...6101ff..."` (`any`) |
| `the_frames_written_before_1002_are_refused_or_misread_by_the_reference_1002` | the frame written for `any` is the recorded base frame |
| `the_label_query_mode_reader_reads_the_byte_as_the_reference_processor_does_1002` | `left: Some(All)`, `right: Some(Any)` |
| `the_optional_query_mode_helpers_are_the_recorded_label_query_mode_bytes_1002` | `left: 0`, `right: 1` |
| `every_recorded_request_frame_is_the_frame_this_crate_writes_1002` | the two `labelQueryMode` rows of 61 |
| `the_processor_refuses_a_request_flag_outside_its_range_in_the_reference_frame_1002` | `invalid boolean flag: expected -1, 0, or 1, got 2` for `Invalid forSelf flag: expected -1, 0, or 1, received 2` |
| `a_presence_flag_of_an_action_result_other_than_0_or_1_is_refused_1002` | `createAction txid present = 2`: `Wallet Wire createAction noSendChange count exceeds the remaining response data`; the `tx` and `signableTransaction` flags read as absent |
| `a_listed_action_status_outside_1_to_8_is_refused_1002` | `invalid action status code: 0`; 255 read as `unprocessed` |
| `a_listed_action_boolean_other_than_0_or_1_is_refused_1002` | `invalid boolean flag: ...`; 255 read as `false` |
| `an_authentication_verdict_is_exactly_one_byte_0_or_1_1002` | 255 read as `false`, two bytes read as `true` |
| `a_network_answer_is_exactly_one_byte_0_or_1_1002` | `unknown network code: 2`; two bytes read as `mainnet` |
| `a_verifier_length_other_than_0_or_33_is_refused_1002` | `invalid listCertificates verifier length: ...` (lower case) |
| `every_recorded_result_frame_reads_to_the_reference_value_1002` | `listActions_labels_empty`: no `labels` where the reference reads `[]`; `listOutputs_tags_labels_empty` refused (a probe on the same scratch copy: `Invalid listOutputs result outputs[0].tags: expected the explicitly requested output tags`) |
| `the_public_result_writers_write_the_reference_processor_frames_1002` | `listActions status: completed`: `...7473 00 0100...` for `...7473 ffffffffffffffffff 0100...` |
| `the_action_status_helpers_are_the_recorded_status_bytes_1002` | `invalid action status code: 0` |
| `an_absent_tag_list_and_an_empty_script_are_written_otherwise_stated_1002` | the frames around the stated bytes carry the base's `00` for absent `tags` and `labels` |

Green on both: `a_keyring_flag_other_than_0_or_1_is_refused_1002` (an agreement pin, #183), `the_optional_bool_helpers_are_the_recorded_optional_boolean_bytes_1002`, `the_unused_mode_helpers_write_no_methods_bytes_stated_1002`.

Each change alone, planted back in a scratch copy of the tip (21 plants, one at a time, the same test binary): every plant RED on the tests that name its finding (the writer's 0 and 1: 4 tests; the reader's: 2; each of the three presence flags: 1; -1 as `unprocessed`: 1; `isOutgoing` and `spendable` lenient: 1 each; the single byte without its length check, and another byte read as `false`: 2 each; an empty list read as absent, for each of the three lists: 1; an absent list written as a count of 0, for each of the three: 1 or 2; each refusal's old words: 1 or 2; `seekPermission` named otherwise: 1).

## Mutants

`cargo mutants` 27.1.0, `--features "full,http"`, one job, the wire test binaries named with `-C --test=` (`wallet_wire_flags_1002`, `wallet_wire_cross_sdk_tests`, `wire_method_roundtrip_tests`, `wire_processor_validation`, `wire_error_frames`, and for the result side `wallet_wire_result_validation_487`, `wire_send_with_status_590`, `wallet_wire_bounds_473`, `wire_reader_strictness`, for the requests `wire_linkage_calls_406`), in shards that each ended inside ten minutes:

| File | Mutants | Caught | Unviable | Missed |
|---|---:|---:|---:|---:|
| `src/wallet/wire/flags.rs` (whole) | 18 | 16 | 2 | 0 |
| `src/wallet/wire/bounds.rs` (`read_optional_response_strings`) | 5 | 5 | 0 | 0 |
| `src/wallet/wire/transceiver.rs` (`is_authenticated`, `get_network`, `create_action`, `sign_action`) | 8 | 7 | 1 | 0 |
| `src/wallet/wire/encoding.rs` (the two query-mode helpers, `read_action_status`, the action and output readers and writers) | 16 | 11 | 5 | 0 |
| `src/wallet/wire/requests.rs` (whole) | 38 | 26 | 12 | 0 |

Not the nightly's measure: its wire surface runs under `full,http,tracing` with its own selection.

## What moved beside the code

- `tests/fixtures/wire/listActions.json`: the `full` case's `request_hex`, one byte (`...6f6d656761 01 01...` to `...6f6d656761 02 01...`, `labelQueryMode: "all"`), recorded with `BSV_FIXTURES_RECORD=1`. No other fixture moved.
- `tests/wire_certificate_frames.rs`: `a_listed_verifier_of_another_length_is_refused` expects the reference's capital.
- No shared vector was edited; `flags_1002.json` is new.

## The gate (2026-11-15, the Studio, `CARGO_BUILD_JOBS=2` while the host's swap sat above half)

- Rustfmt, the lint job's three lines on `beta` (`cargo fmt --all -- --check`, `--manifest-path fuzz/Cargo.toml`, `--manifest-path fuzz/corpus-gen/Cargo.toml`): clean.
- `cargo +1.100.0 clippy --all-targets --all-features -- -D warnings`: exit 0 (four manifest warnings of cargo 1.100.0 on `Cargo.toml`, a file this lane does not touch); the `wallet` slice alone: exit 0.
- `cargo check --all-targets --all-features`: finished.
- The wallet module's unit tests (`--lib wallet::`), three runs, one with `--test-threads=1`: 186 passed each.
- The test files of the wire and the wallet, by glob (`wallet_*`, `wire_*`) with `transport_fault_wallet`, `abort_kind_604`, `auth_certificate_field_bound_275` and `primitives_sec1_tag_05_550` (every test file that names a wire type), `--features "full,http"`, three runs, one with `--test-threads=1`, and a fourth after the last change: 64 binaries, 830 passed, 0 failed, 1 ignored each. `wallet_wire_flags_1002` alone, three runs, one single-threaded: 19 passed each.
- `arch_*` (38), `fixtures_replay`, `readme_examples`, `front_page`, `wire_codec_bench_bytes`: 42 binaries, 215 passed, 0 failed, 1 ignored.
- `RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --all-features`: exit 0. `cargo test --doc --all-features`: 384 passed, 128 ignored.
- `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`: finished.
- `tools/ratchet/run --check --against origin/beta`: all 7 counters, oversized-file limits and mutation floors pass (`encoding.rs` 2,399 lines against its bound of 2,490, 2,436 on the base; `transceiver.rs` 1,465 against 1,643, 1,495 on the base; `flags.rs` is new, 114 lines). Measured at `d892e206` (`--revision`) and at the tip: functions over 60 lines 75 and 73, duplicate windows 7,112 and 7,018, pedantic warnings 2,659 and 2,656, the other four equal.
- `python3 .github/scripts/mutants_entries.py`: 28 entries, each one listed mutant. `python3 .github/scripts/rows_from_sources.py --check`: 0 refusals.
- gitleaks 8.30.1, git mode, over `origin/beta..HEAD` (`gitleaks git --redact --no-banner --exit-code 1 -v --log-opts="origin/beta..HEAD" .`): no leaks found, one commit scanned. A run before the two key-named members took the generator point found four (`generic-api-key` on `senderIdentityKey` and `identityKey` holding the public key of 9); the recorder was changed, not the configuration.

## What was not verified

- No Linux, Windows or beta-toolchain run: CI's, after the landing.
- The whole integration suite was not run: the gate is the wallet and wire files by glob, every test file that names a wire type, and the arch set.
- go-sdk was read, not run. The reference's head was read for the three modes alone.
- The nightly's mutation measure of the wire surface (`full,http,tracing`, its own selection) was not run; the table above is this lane's narrower run.
- No dependent was built against the change. The two local clones searched (the toolbox, the CLI) name neither changed helper outside tests.
