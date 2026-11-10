# Lane filings-1109: the upstream filing queue brought up to date (#375)

Started from `4e57b23f53dcf271ed19a34a22c1aeab66fd6789`, `origin/beta`'s tip on 2026-11-09 (no reset needed). Documents only: no source, no test, no cargo run, nothing filed on any repository. Logs under `/Volumes/Lanes/out/bsv-rs/filings-1109/`.

The owner asked on 2026-11-09 whether the references need upstream issues. The standing answer is the main-merge gate of #375 (RELEASING.md point 16): every row of `CLAUDE.md`'s "Known cross-SDK divergences" carries a filing number on the other SDK's repository, or "ours" with its reading. This record reads every divergence row and parity note since 0.9.0-beta.6 (the `## [Unreleased]` and `## [0.9.0-beta.7]` sections of `CHANGELOG.md`, the `CLAUDE.md` rows changed since the `v0.9.0-beta.6` tag) and the open pull requests' notes, and classifies each.

Reading: "ours" is this crate's choice, with the reading that justifies it; "theirs" is the other SDK departing from the node, a BRC, its sibling SDK or its own stated rule in a way its user meets. Each claim below was read at the pins (`ts-stack@edf6e03`, `go-sdk@2ca481c`, bitcoin-sv `v1.2.2`, BRCs `5119a9b`).

## The table

| # | Row or note (issue) | Ours (reading) | Theirs | Filing |
|---|---|---|---|---|
| 1 | Attribute matcher and question bounds (#751, #756) | the reference wallet's matcher; residues (lone attribute as `any`, page before filter, case tables) by the keeper's reading of 2026-11-04 07:1xZ; #756 hardening | none (the SDK client checks nothing; Go asks its wallet) | none needed |
| 2 | Lookup limits (#775, #785) | the reference's limits; five stated residues; the 4096 normalizer constant by the captain's ruling of 2026-11-09 | go-sdk: the count's capacity panics and an index past 32 bits is truncated (`facilitator.go:96,128`); the byte bounds are the reference's safeguards, Go's choice (the keeper's 2026-10-30 08:1xZ line) | row 34, unfiled |
| 3 | `AbortAcceptance` kind (#604) | a port addition beside #439; no wire byte moves | none | none needed |
| 4 | Resolver merge and the txid hint (#796) | the disagreeing output kept and counted, the owner's word on #735 (2026-11-04 13:5xZ) | ts-stack: the hint's reading; go-sdk: a later copy replaces the earlier, map order (`resolver.go:131-148`) | ts-stack #1482; go-sdk row 37, unfiled |
| 5 | SHIP discovery admission (#804) | closed at the pin; residues stated (types, the resolver's drop, map order) | go-sdk: no value, signature or hint check (`broadcaster.go:278-299`); the unchecked index panics (`:283`) | rows 33 and 35, unfiled |
| 6 | Atomic subject written twice (#731) | both read the later entry | none | none needed |
| 7 | Offset-0 proof under 100 blocks (#734) | the reference's rule at `Transaction::verify` by the keeper's word of 2026-11-04 02:2xZ; the stream keeps the node's | ts-stack: refuses at a tip of `h + 99` and a proven coinbase nothing spends, stricter than the node (`validation.cpp:2546-2550,2617-2625`); go-sdk follows the node (candidate dropped) | row 31, unfiled |
| 8 | SLAP discovery admission (#786) | closed at the pin | go-sdk: no value, signature or hint check (`resolver.go:184-208`) | row 35, unfiled |
| 9 | PushDrop wallet lock (#782) | two residues (the key text parsed; #545's odd-length opcode) | go-sdk: key re-encoded compressed, signature re-serialized (`pushdrop.go:136,160`) | row 40, unfiled |
| 10 | Lookup output's txid hint at the identity evidence (#735) | read and counted, the owner's word of 2026-11-04 13:5xZ | ts-stack: the reference skips | ts-stack #1482 |
| 11 | Atomic writer's txid-only entry (#766) | closed at the pin | none | none needed |
| 12 | SLAP tracker selection (#769) | every tracker asked, a liveness difference; a row if the keeper wants the cursor | none | none needed |
| 13 | Mutation oracle's timeout class (#781) | no SDK behaviour | none | none needed |
| 14 | `resolve_by_identity_key` as a list (#737) | the unported trust settings and page (#754's record) | ts-stack: grouping by the subject's text | ts-stack #1483 |
| 15 | `RPuzzle.lock` past 76 bytes (#603) | the minimal push; no puzzle either SDK can spend crosses the gap | latent in ts-stack, unreachable by a spendable puzzle (candidate dropped) | none |
| 16 | PushDrop decode at the public door and the canonical path (#603, #618, census row 93) | the public door the reference's; the canonical path refuses where every reference site refuses | the row says go-sdk refuses what the reference's `decode` reads; dropped as a filing (see below) | none (row 93 a re-read for the keeper) |
| 17 | The seven key calls' validators (#609) | the reference's | none (Go validates nothing, no divergence stated) | none needed |
| 18 | `find_transaction_for_signing` links (#603) | a clone, the BEEF unchanged; residues stated | none | none needed |
| 19 | A bare `OP_RETURN` (#603 shard B) | the node's reading (`script.h:163-198`, `core_write.cpp:100-176`) | ts-stack: `toASM` prints `''` and drops the opcode of every folded `OP_RETURN` | row 32, unfiled |
| 20 | MerklePath height bound and combine (#603) | BRC-74's 64 levels; combine keeps the root | ts-stack: both bugs; go-sdk: the longer-receiver combine | ts-stack #1469, #1470; go-sdk #411 |
| 21 | MerklePath with no levels (#649) | refused at every door | none (no verdict differs) | none needed |
| 22 | The key encoding check (#660) | the node's reading in every mode, the keeper's word of 2026-11-02 23:2xZ | ts-stack: an off-curve key refused at the encoding check under the default and under `STRICTENC` (`Spend.ts:711-716`), valid at the node | row 30, unfiled |
| 23 | P2PK and Multisig lock key tags (#625) | a door the reference does not have; no verdict differs | none | none needed |
| 24 | The CHECKSIG scriptCode (#654) | the node's bytes | ts-stack: the `OP_RETURN` stop | row 27, unfiled |
| 25 | The chunker's IF depth (#634) | the reference's reading, the keeper's word of 2026-11-02 22:1xZ | ts-stack: `68636a5168`; go-sdk: `DecodeScript` at a negative depth; the ASM clause row 32 | rows 26, 28, unfiled |
| 26 | CHECKMULTISIG encoding words (#657) | closed; the x = p + 1 residue closed by #660 | none | none needed |
| 27 | Contacts update and removal words (#718) | native words, no cause chain | none | none needed |
| 28 | Hand-built chunk texts (#661) | the reference's reading; `OP_UNKNOWN<n>` against `undefined` | latent in ts-stack, no byte form carries it (dropped) | none |
| 29 | `OP_0` and `OP_1NEGATE` names (#723) | closed, the reference's names (the keeper's word of 2026-11-03 23:1xZ) | none | none needed |
| 30 | Identity evidence residues (#725, #728, #730) | the coordinator's tracker verify unported (#553's residue) | none | none needed |
| 31 | `discover_certificates` (#739) | the wallet door's trust step and page unported | none | none needed |
| 32 | Semantic HTTP rejection neutral (#760) | every non-2xx a failure here, a residue | none | none needed |
| 33 | Strict sibling-leaf match (#757, #765) | reversed, the reference's | none | none needed |
| 34 | Formula answer (#762) | read as `Formula`, a residue | none | none needed |
| 35 | `Beef::merge_transaction` (#764) | linear storage by Rust ownership | go-sdk: a held BUMP not attached, sources walked (`beef.go:858-915`) | row 38, unfiled |
| 36 | The empty ASM text (#603 shard A) | held as the empty script with go-sdk, the owner's word of 2026-11-04 13:5xZ | ts-stack | ts-stack #1479 |
| 37 | JSON lookup answer shapes (#768) | the normalizer's refusals; `formula` and the unknown-type words residues | go-sdk: `Beef []byte` written as base64, refused by the reference | row 39, unfiled |
| 38 | Key forms on the hex path (#498, touched since beta.6) | the keeper's word of 2026-10-30 05:1xZ | ts-stack: the unreduced coordinate written back | ts-stack #1467 |
| 39 | HTTP JSON result validator (#432, touched) | R02, R03, R47 stated | go-sdk | go-sdk #406 |
| 40 | Discovery trust byte (#183, touched) | native field-prime refusal | go-sdk | go-sdk #404 |
| 41 | `unlockingScriptLength` of 0 (#282, touched) | BRC-100 `wallet/0100.md:649` | ts-stack, go-sdk | ts-stack #1466; go-sdk #403 |
| 42 | Certificate bounds and DER (#275, touched) | the reference's safeguards | go-sdk: high-S rewritten | go-sdk #401 |
| 43 | Certificate response preimage (#375, #400, touched) | the reference's order | go-sdk | go-sdk #402 (BRCs: filing pending, older than beta.6) |
| 44 | Wire linkage calls (#406, touched) | native refusal words | go-sdk | go-sdk #405 |
| 45 | Identity record checks (#553, touched) | residues stated | none | none needed |
| 46 | Transaction version sign (#418, open PR #812) | the default reads unsigned, as the reference | ts-stack: explicit flags relax a version at or above 2^31 | row 29 (PR #812's draft), unfiled |
| 47 | Atomic writer, a raw entry naming no matching BUMP (#798, open PR #809) | the reference's bytes; the `toHex`-dependent order stated as ours | go-sdk keeps and remaps the BUMP (dropped); ts-stack's order (dropped) | none |
| 48 | Default push-only rule (#816, open PR #822) | this crate's own, open before the owner | none | none needed |
| 49 | Freeform answer precedence (#815, open PR #821) | closed at the pin | go-sdk: a freeform answer arriving soonest wins (`resolver.go:122-124`) | row 37, unfiled |
| 50 | Topic broadcaster requirements (open PR #820) | closed at the pin | go-sdk: the all-hosts requirement over successful hosts alone (`broadcaster.go:174-211`) | row 36, unfiled |
| 51 | `merge_beef` txid reuse (#621, open PR #823) | no observable difference | none | none needed |

PRs #824 (#104) and #825 (#689) carry no parity note.

Counts: 51 rows read. Every row carries an ours reading (or no divergence, or closed at the pin). 26 rows carry a "theirs" as well. "Theirs" filed: 12 rows, 14 numbers (ts-stack #1466, #1467, #1469, #1470, #1479, #1482, #1483; go-sdk #401, #402, #403, #404, #405, #406, #411). "Theirs" unfiled: 15 rows (row 4 is both), covered by 15 drafts: queue rows 26, 27 and 28 (drafted earlier), row 29 (PR #812's draft) and the eleven new drafts, rows 30 to 40.

## The new drafts (queue rows 30 to 40)

| Row | Repository | Draft | Title |
|---|---|---|---|
| 30 | ts-stack | `375-filings/spend-pubkey-encoding-point-check-ts-stack.md` | Spend refuses an off-curve public key at the encoding check, where the node passes it to the signature check and lets `OP_CHECKSIG OP_NOT` succeed |
| 31 | ts-stack | `375-filings/merkle-path-verify-coinbase-depth-ts-stack.md` | MerklePath.verify refuses an offset-0 proof one block before the node would mine its spend, and refuses a proven coinbase that nothing spends |
| 32 | ts-stack | `375-filings/script-to-asm-op-return-ts-stack.md` | Script.toASM drops the OP_RETURN opcode of every script that ends in an OP_RETURN, so fromASM reads back a different script |
| 33 | go-sdk | `375-filings/ship-discovery-output-index-panic-go-sdk.md` | Broadcaster.FindInterestedHosts panics on a SHIP lookup output whose outputIndex is past the transaction's outputs |
| 34 | go-sdk | `375-filings/binary-lookup-answer-count-and-index-go-sdk.md` | parseBinaryLookupAnswer allocates from an unbounded outpoint count and truncates an output index past 32 bits |
| 35 | go-sdk | `375-filings/overlay-discovery-advertisement-admission-go-sdk.md` | SLAP and SHIP host discovery admit a host from an advertisement that is unsigned, of any value, or for another transaction |
| 36 | go-sdk | `375-filings/topic-broadcaster-all-hosts-requirement-go-sdk.md` | An all-hosts acknowledgment requirement passes when an interested host failed, because only the successful hosts are checked |
| 37 | go-sdk | `375-filings/lookup-query-merge-go-sdk.md` | LookupResolver.Query returns a lone freeform answer over every other host's outputs, lets a later copy of an outpoint replace the earlier, and returns the outputs in map order |
| 38 | go-sdk | `375-filings/beef-merge-held-bump-go-sdk.md` | Beef.MergeTransaction does not attach a BUMP the Beef already holds for the transaction, so the transaction is stored unproven and its sources are walked |
| 39 | go-sdk | `375-filings/lookup-answer-json-beef-encoding-go-sdk.md` | OutputListItem writes its BEEF as a base64 string in JSON, which the TypeScript lookup client refuses |
| 40 | go-sdk | `375-filings/pushdrop-lock-wallet-bytes-go-sdk.md` | PushDrop.Lock re-encodes the wallet's public key as compressed and re-serializes its signature, so a token's bytes differ from the TypeScript lock for the same wallet answer |

Three against ts-stack, eight against go-sdk. Row 29 (`transaction-version-sign-ts-stack.md`, #418) is PR #812's and is not written again; the queue numbers this lane's rows from 30 so both land without renumbering.

## Candidates dropped

- go-sdk `MerklePath.Verify` with no depth rule and `spv.Verify` judging a coinbase source (#734): go-sdk follows the node (`spv/verify.go:701-714`, `tip + 1 - height >= 100`, as `validation.cpp:2546-2550,2617-2625`); the divergence is the reference's, row 31.
- The TypeScript SHIP broadcaster's 64 MiB total BEEF budget behind its resolver's limits (#775 with #804): `MAX_SHIP_TOTAL_ADVERTISEMENT_BEEF_BYTES` is 64 MiB (`SHIPBroadcaster.ts:100`) and the default resolver retains at most `maxTotalBytes` 64 MiB (`LookupResources.ts:23`, `LookupResolver.ts:1741-1742`), so the check is unreachable with the default resolver and live with a caller's own; no verdict a user meets differs.
- The TypeScript atomic writer's order after `toHex` (#798, PR #809): `#copySelectedTransactions` takes the raw branch once an entry's `_rawTx` cache is filled (`Beef.ts:464-467`), so the order moves, but only for a `Transaction`-held entry whose BUMP index was set by hand to name no matching BUMP; both orders read the same under every reader, and PR #809 states it as ours.
- go-sdk's `includeAtomicBump` keeping and remapping a BUMP that does not hold the entry's txid (#798, `beef.go:1773-1787`): the input is itself a BEEF no valid writer produces (an index naming no BUMP with its txid); garbage in, the shape kept.
- go-sdk's public `pushdrop.Decode` refusing a key-only script and a token without `OP_CHECKSIG` second (#618, census row 93, "Theirs: go-sdk, no filing made"): every reference validator refuses both shapes (`PushDropValidation.ts:54-79`, `IdentityClient.ts:130-147`, `ContactsManager.ts:225-242`), so the ask would be for go-sdk to read tokens the reference's own validators refuse. Recommended to the keeper as a re-read of row 93's "theirs" clause.
- The TypeScript `RPuzzle.lock` past 76 bytes (#603) and the hand-built chunk texts (#661): real in the reference's code, reached by no puzzle either SDK can spend and by no byte form, so no user meets them.
- The TypeScript query's semantic HTTP rejection kept neutral (#760): this crate's residue, not the reference's defect.

## Rows 26 to 28

From `QUEUE.md` and #375's comments (the last, of 2026-11-02 13:26Z, records the eleven-row batch and says the queue had no unfiled row left; rows 26 to 28 were added after it):

- Row 26 (`script-if-depth-negative-ts-stack.md`, ts-stack): unfiled, waits; its status line says the keeper files it the day the draft is read.
- Row 27 (`sighash-scriptcode-op-return-stop-ts-stack.md`, ts-stack): unfiled, waits. Its file carries no `keeper's word first` or FILE line; the keeper may want one.
- Row 28 (`script-chunker-if-depth-clamp-go-sdk.md`, go-sdk): unfiled, waits, after rows 26 and 27.

No comment on #375 names a number for any of them.

## Older rows still unfiled (outside this lane's window)

The gate is not met by the rows above alone. Rows of `CLAUDE.md`'s list older than beta.6 still say "Theirs: ..., filing pending" with no draft in the queue: go-sdk on #333 (ECIES bounds), #353 and #445 (Peer), the overlay admin token's counterparty, #163 (BIP-39 NFKD), #197, #202, #206 (wire frames), #261/#394 (certificate JSON), #323, #294, #109, the transport client hook (#320), #326, #416, #487, #543, #548, #545; ts-stack on #331 and #416; the BRCs on #280/#426/#400 and #369/#448. Several have drafts under other names in `375-filings/` (`wire-false-verdicts.md`, `wire-error-frames.md`, `wire-abort-refusal.md`, `peer-pinned-identity.md`, `bip39-nfkd.md`, `ecies-byte-bounds.md`, `electrum-envelope-key-detection.md`, `overlay-admin-derivation.md`, `requested-certificate-set-validation.md`, `peer-certificate-count-bound.md`, `auth-http-*.md`, `signed-header-sort.md`, `local-kvstore-wallet-contract.md`) that are neither rows of the queue table nor named in the keeper's per-draft word of 2026-10-30 07:14Z on #375; their status was not traced by this lane. A lane for them is the next step if the gate is to close.

## Checks

`python3 -B .github/scripts/rows_from_sources.py --check` run before the commit; no em dash in any file written. No cargo was run.
