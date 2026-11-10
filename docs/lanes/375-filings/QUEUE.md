# Filing queue for #375

The keeper files under the owner's name only on the owner's cadence word
(21.5 of the 2026-10-30 brief). Nothing in this queue is authorization to file.
After filing, put the filed number on bsv-rs#375 and in the row's verdict clause.
The review briefs under `docs/lanes/` are not filings.

The keeper read the seventeen keeper-first drafts at `859116f1` and gave
[the per-draft word](https://github.com/Calhooon/bsv-rs/issues/375#issuecomment-6517160425) at 07:14Z on 2026-10-30.
The sixteen approved drafts are FILE in that relative order of consequence, pending the owner's
cadence word; the keeper recommends a few a day per repository, with later
threads following answers to the earlier ones.

| Order | Repository | Draft path | Title |
|---|---|---|---|
| 1 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/wire-originator.md](./wire-originator.md) | Prevent originator length wrapping and normalize wallet wire originators (filed as bsv-blockchain/go-sdk#399 on 2026-11-01 under the owner's name (cadence (b), the owner's word of 2026-10-31 16:2xZ through the keeper); answer pending) |
| 2 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/wire-numeric-collection-bounds.md](./wire-numeric-collection-bounds.md) | Check wallet response widths and collection counts before reading or allocating (filed as bsv-blockchain/go-sdk#400 on 2026-11-01 under the owner's name (cadence (b), the owner's word of 2026-10-31 16:2xZ through the keeper); answer pending) |
| 3 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/merkle-lone-leaf-offset.md](./merkle-lone-leaf-offset.md) | Reject a one-transaction Merkle proof with a nonzero leaf offset (filed as bsv-blockchain/ts-stack#1460 on 2026-10-31 under the owner's name (cadence (b), the owner's word of 16:2xZ through the keeper); answer pending) |
| 4 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/beef-empty-transactions.md](./beef-empty-transactions.md) | Reject raw zero-input and zero-output transactions in BEEF structure validation (filed as bsv-blockchain/ts-stack#1461 on 2026-10-31 under the owner's name (cadence (b), the owner's word of 16:2xZ through the keeper); answer pending) |
| 5 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/atomic-unrelated-data.md](./atomic-unrelated-data.md) | Enforce the subject dependency graph when validating parsed Atomic BEEF (filed as bsv-blockchain/go-sdk#396 on 2026-10-31 under the owner's name (cadence (b), the owner's word of 16:2xZ through the keeper); answer pending) |
| 6 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/beef-duplicate-offsets-go-sdk.md](./beef-duplicate-offsets-go-sdk.md) | Reject contradictory repeated BUMP offsets (filed as bsv-blockchain/go-sdk#397 on 2026-10-31 under the owner's name (cadence (b), the owner's word of 16:2xZ through the keeper); answer pending) |
| 7 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/beef-reserved-flags-ts-stack.md](./beef-reserved-flags-ts-stack.md) | Reject reserved BEEF discriminators (filed as bsv-blockchain/ts-stack#1462 on 2026-10-31 under the owner's name (cadence (b), the owner's word of 16:2xZ through the keeper); answer pending) |
| 8 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/canonical-varint-reader.md](./canonical-varint-reader.md) | Provide a canonical CompactSize reader for protocol parsing (filed as bsv-blockchain/go-sdk#398 on 2026-10-31 under the owner's name (cadence (b), the owner's word of 16:2xZ through the keeper); answer pending) |
| 9 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/certificate-bounds-der.md](./certificate-bounds-der.md) | Certificate wallet conversion rewrites valid high-S signature bytes (filed as bsv-blockchain/go-sdk#401 on 2026-11-02 under the owner's name (cadence (b), the keeper's detached script at 00:00Z from the draft as it stood on beta); answer pending) |
| 10 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/certificate-response-preimage-go-sdk.md](./certificate-response-preimage-go-sdk.md) | Preserve certificate-response property order when signing and verifying (filed as bsv-blockchain/go-sdk#402 on 2026-11-02 under the owner's name (cadence (b), the keeper's detached script at 00:00Z from the draft as it stood on beta); answer pending) |
| 11 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/certificate-outpoint-bound.md](./certificate-outpoint-bound.md) | Reject certificate outpoint indexes that the writer cannot serialize (filed as bsv-blockchain/ts-stack#1463 on 2026-11-01 under the owner's name (cadence (b), the owner's word of 2026-10-31 16:2xZ through the keeper); answer pending) |
| 12 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/wire-input-index-width.md](./wire-input-index-width.md) | Bound internalizeAction outputIndex consistently with PositiveIntegerOrZero (filed as bsv-blockchain/ts-stack#1464 on 2026-11-01 under the owner's name (cadence (b), the owner's word of 2026-10-31 16:2xZ through the keeper); answer pending) |
| 13 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/create-action-positive-script-length-ts-stack.md](./create-action-positive-script-length-ts-stack.md) | Refuse zero unlockingScriptLength as BRC-100 specifies (filed as bsv-blockchain/ts-stack#1466 on 2026-11-02 under the owner's name (cadence (b), the keeper's detached script at 00:00Z from the draft as it stood on beta); answer pending) |
| 14 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/create-action-positive-script-length-go-sdk.md](./create-action-positive-script-length-go-sdk.md) | Validate positive createAction unlockingScriptLength (filed as bsv-blockchain/go-sdk#403 on 2026-11-02 under the owner's name (the owner's word of 2026-11-02 13:2xZ through the keeper, the eleven remaining rows as one batch from the drafts as they stood on beta; the keeper's record filings-20261102-batch.txt on the stack); answer pending) |
| 15 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/discovery-trust-range.md](./discovery-trust-range.md) | Validate discovery certificate trust on read and write (filed as bsv-blockchain/go-sdk#404 on 2026-11-02 under the owner's name (the owner's word of 2026-11-02 13:2xZ through the keeper, the eleven remaining rows as one batch from the drafts as they stood on beta; the keeper's record filings-20261102-batch.txt on the stack); answer pending) |
| 16 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/linkage-reason-and-result-validation.md](./linkage-reason-and-result-validation.md) | Use the linkage reason width and validate returned linkage context (filed as bsv-blockchain/go-sdk#405 on 2026-11-02 under the owner's name (the owner's word of 2026-11-02 13:2xZ through the keeper, the eleven remaining rows as one batch from the drafts as they stood on beta; the keeper's record filings-20261102-batch.txt on the stack); answer pending) |
| 17 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/http-json-result-validation.md](./http-json-result-validation.md) | Validate HTTP wallet results against their requests and BRC-100 shapes (filed as bsv-blockchain/go-sdk#406 on 2026-11-02 under the owner's name (the owner's word of 2026-11-02 13:2xZ through the keeper, the eleven remaining rows as one batch from the drafts as they stood on beta; the keeper's record filings-20261102-batch.txt on the stack); answer pending) |
| 18 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/public-key-unreduced-coordinate-serialization.md](./public-key-unreduced-coordinate-serialization.md) | Reduce or refuse an unreduced public key coordinate at parse, and serialize the point computed with rather than the coordinates given (filed as bsv-blockchain/ts-stack#1467 on 2026-11-02 under the owner's name (cadence (b), the keeper's detached script at 00:00Z from the draft as it stood on beta); answer pending) |
| 19 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/decode-outpoints-count-bound-go-sdk.md](./decode-outpoints-count-bound-go-sdk.md) | Bound the outpoint count read off the wire by the body's remaining bytes before allocating (filed as bsv-blockchain/go-sdk#407 on 2026-11-02 under the owner's name (the owner's word of 2026-11-02 13:2xZ through the keeper, the eleven remaining rows as one batch from the drafts as they stood on beta; the keeper's record filings-20261102-batch.txt on the stack); answer pending) |
| 20 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/no-send-change-framing-go-sdk.md](./no-send-change-framing-go-sdk.md) | createAction's noSendChange is framed behind an extra byte length, so a Go wallet and a TypeScript client cannot read each other's list (filed as bsv-blockchain/go-sdk#408 on 2026-11-02 under the owner's name (the owner's word of 2026-11-02 13:2xZ through the keeper, the eleven remaining rows as one batch from the drafts as they stood on beta; the keeper's record filings-20261102-batch.txt on the stack); answer pending) |
| 21 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/send-with-results-marker-go-sdk.md](./send-with-results-marker-go-sdk.md) | createAction and signAction results: an absent sendWithResults panics on the wire's absent marker, and a nil one is written as a zero count instead of the marker (filed as bsv-blockchain/go-sdk#409 on 2026-11-02 under the owner's name (the owner's word of 2026-11-02 13:2xZ through the keeper, the eleven remaining rows as one batch from the drafts as they stood on beta; the keeper's record filings-20261102-batch.txt on the stack); answer pending) |
| 22 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/create-action-result-success-byte-go-sdk.md](./create-action-result-success-byte-go-sdk.md) | createAction's result carries an extra success byte inside the frame that the wire does not define, so a Go client refuses every TypeScript result that carries a txid and a TypeScript client misreads Go's (filed as bsv-blockchain/go-sdk#410 on 2026-11-02 under the owner's name (the owner's word of 2026-11-02 13:2xZ through the keeper, the eleven remaining rows as one batch from the drafts as they stood on beta; the keeper's record filings-20261102-batch.txt on the stack); answer pending) |
| 23 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/merkle-path-height-bound-ts-stack.md](./merkle-path-height-bound-ts-stack.md) | Bound MerklePath height at BRC-74's 64 levels rather than 54 (filed as bsv-blockchain/ts-stack#1469 on 2026-11-02 under the owner's name (the owner's word of 2026-11-02 13:2xZ through the keeper, the eleven remaining rows as one batch from the drafts as they stood on beta; the keeper's record filings-20261102-batch.txt on the stack); answer pending) |
| 24 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/merkle-path-combine-shorter-receiver-ts-stack.md](./merkle-path-combine-shorter-receiver-ts-stack.md) | Combine a longer MerklePath into a shorter receiver over the union of levels so the root is the checked root (filed as bsv-blockchain/ts-stack#1470 on 2026-11-02 under the owner's name (the owner's word of 2026-11-02 13:2xZ through the keeper, the eleven remaining rows as one batch from the drafts as they stood on beta; the keeper's record filings-20261102-batch.txt on the stack); answer pending) |
| 25 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/merkle-path-combine-longer-receiver-go-sdk.md](./merkle-path-combine-longer-receiver-go-sdk.md) | Combine files the receiver's level-1 nodes under level 0 when the receiver is the longer path and returns no error (filed as bsv-blockchain/go-sdk#411 on 2026-11-02 under the owner's name (the owner's word of 2026-11-02 13:2xZ through the keeper, the eleven remaining rows as one batch from the drafts as they stood on beta; the keeper's record filings-20261102-batch.txt on the stack); answer pending) |
| 26 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/script-if-depth-negative-ts-stack.md](./script-if-depth-negative-ts-stack.md) | Script.fromBinary folds OP_RETURN inside an open OP_IF as top level after a stray OP_ENDIF (narrowed by the keeper's word of 2026-11-02 22:1xZ to `68636a5168`; the `686a51` reading is the reference's and bsv-rs's since #634's fold; the toASM round trip an observation, not asked; unfiled: the keeper files it the day the draft is read) |
| 27 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/sighash-scriptcode-op-return-stop-ts-stack.md](./sighash-scriptcode-op-return-stop-ts-stack.md) | Spend's CHECKSIG scriptCode drops every byte after a top-level OP_RETURN, so an unlocking-script check signs a different digest than the node (unfiled; drafted by the #654 lane on 2026-11-02; the keeper files it) |
| 28 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/script-chunker-if-depth-clamp-go-sdk.md](./script-chunker-if-depth-clamp-go-sdk.md) | DecodeScript reads a negative IF depth as the top level, so OP_RETURN after a stray OP_ENDIF swallows the rest of the script (from #634's fold, the keeper's word of 2026-11-02 22:1xZ: the ask to fold only at depth 0 as the reference does, six of fifteen shapes apart; unfiled; after rows 26 and 27, row 27 #658's) |
| 29 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/transaction-version-sign-ts-stack.md](./transaction-version-sign-ts-stack.md) | Spend's explicit flags read a transaction version at or above 2^31 as malleable, where the node and go-sdk read it as a negative int32 (from #418: the ask `(this.transactionVersion \| 0) > 1` in `#enforceNonMalleability`; the default mode's unsigned reading is the reference's and bsv-rs's since #418; unfiled) |
| 30 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/spend-pubkey-encoding-point-check-ts-stack.md](./spend-pubkey-encoding-point-check-ts-stack.md) | Spend refuses an off-curve public key at the encoding check, where the node passes it to the signature check and lets `OP_CHECKSIG OP_NOT` succeed (from #660; unfiled; drafted by the filings-1109 lane on 2026-11-09; the keeper's word first) |
| 31 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/merkle-path-verify-coinbase-depth-ts-stack.md](./merkle-path-verify-coinbase-depth-ts-stack.md) | MerklePath.verify refuses an offset-0 proof one block before the node would mine its spend, and refuses a proven coinbase that nothing spends (from #734; unfiled; drafted by the filings-1109 lane on 2026-11-09; the keeper's word first) |
| 32 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/script-to-asm-op-return-ts-stack.md](./script-to-asm-op-return-ts-stack.md) | Script.toASM drops the OP_RETURN opcode of every script that ends in an OP_RETURN, so fromASM reads back a different script (from #603 shard B and #634; row 26 leaves this round trip out, this row asks it alone; unfiled; drafted by the filings-1109 lane on 2026-11-09; the keeper's word first) |
| 33 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/ship-discovery-output-index-panic-go-sdk.md](./ship-discovery-output-index-panic-go-sdk.md) | Broadcaster.FindInterestedHosts panics on a SHIP lookup output whose outputIndex is past the transaction's outputs (from #804; unfiled; drafted by the filings-1109 lane on 2026-11-09; the keeper's word first) |
| 34 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/binary-lookup-answer-count-and-index-go-sdk.md](./binary-lookup-answer-count-and-index-go-sdk.md) | parseBinaryLookupAnswer allocates from an unbounded outpoint count and truncates an output index past 32 bits (from #775; beside go-sdk #407; unfiled; drafted by the filings-1109 lane on 2026-11-09; the keeper's word first) |
| 35 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/overlay-discovery-advertisement-admission-go-sdk.md](./overlay-discovery-advertisement-admission-go-sdk.md) | SLAP and SHIP host discovery admit a host from an advertisement that is unsigned, of any value, or for another transaction (from #786, #804 and #544; unfiled; drafted by the filings-1109 lane on 2026-11-09; the keeper's word first) |
| 36 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/topic-broadcaster-all-hosts-requirement-go-sdk.md](./topic-broadcaster-all-hosts-requirement-go-sdk.md) | An all-hosts acknowledgment requirement passes when an interested host failed, because only the successful hosts are checked (from the open PR #820; unfiled; drafted by the filings-1109 lane on 2026-11-09; the keeper's word first) |
| 37 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/lookup-query-merge-go-sdk.md](./lookup-query-merge-go-sdk.md) | LookupResolver.Query returns a lone freeform answer over every other host's outputs, lets a later copy of an outpoint replace the earlier, and returns the outputs in map order (from #796 and the open PR #821 (#815); unfiled; drafted by the filings-1109 lane on 2026-11-09; the keeper's word first) |
| 38 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/beef-merge-held-bump-go-sdk.md](./beef-merge-held-bump-go-sdk.md) | Beef.MergeTransaction does not attach a BUMP the Beef already holds for the transaction, so the transaction is stored unproven and its sources are walked (from #764; unfiled; drafted by the filings-1109 lane on 2026-11-09; the keeper's word first) |
| 39 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/lookup-answer-json-beef-encoding-go-sdk.md](./lookup-answer-json-beef-encoding-go-sdk.md) | OutputListItem writes its BEEF as a base64 string in JSON, which the TypeScript lookup client refuses (from #768; unfiled; drafted by the filings-1109 lane on 2026-11-09; the keeper's word first) |
| 40 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/pushdrop-lock-wallet-bytes-go-sdk.md](./pushdrop-lock-wallet-bytes-go-sdk.md) | PushDrop.Lock re-encodes the wallet's public key as compressed and re-serializes its signature, so a token's bytes differ from the TypeScript lock for the same wallet answer (from #782; beside go-sdk #401; unfiled; drafted by the filings-1109 lane on 2026-11-09; the keeper's word first) |
| 41 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/peer-pinned-identity-go-sdk.md](./peer-pinned-identity-go-sdk.md) | Peer accepts an initialResponse signed by another identity than the one the handshake was started with (from #353; unfiled; drafted by the filings-older-1110 lane on 2026-11-10; the keeper's word first) |
| 42 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/bip39-nfkd-go-sdk.md](./bip39-nfkd-go-sdk.md) | NewSeed hashes the mnemonic and passphrase without NFKD normalization, so a non-ASCII passphrase or phrase seeds other bytes than BIP-39 specifies (from #163; unfiled; drafted by the filings-older-1110 lane on 2026-11-10; the keeper's word first) |
| 43 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/wire-false-verdicts-go-sdk.md](./wire-false-verdicts-go-sdk.md) | The wallet wire turns a refusal into success: a false verifyHmac, verifySignature or waitForAuthentication verdict and a refused abortAction are written as the success frame and read back as true (from #197 and #206; unfiled; drafted by the filings-older-1110 lane on 2026-11-10; the keeper's word first) |
| 44 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/wire-error-frames-go-sdk.md](./wire-error-frames-go-sdk.md) | WalletWireProcessor returns a wallet's refusal as a Go error instead of an error frame, so a wire client never learns the refusal's code (from #202; unfiled; drafted by the filings-older-1110 lane on 2026-11-10; the keeper's word first) |
| 45 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/overlay-admin-token-counterparty-go-sdk.md](./overlay-admin-token-counterparty-go-sdk.md) | OverlayAdminToken.Lock signs and locks a SHIP or SLAP advertisement for counterparty self, so the TypeScript validator refuses every go-sdk advertisement (from census row 26, the overlay admin token; unfiled; drafted by the filings-older-1110 lane on 2026-11-10; the keeper's word first) |
| 46 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/certificate-txid-only-outpoint-go-sdk.md](./certificate-txid-only-outpoint-go-sdk.md) | A certificate whose revocationOutpoint is a bare txid, the TypeScript issuer's default, cannot be read from JSON by go-sdk (from #261 and #268; unfiled; drafted by the filings-older-1110 lane on 2026-11-10; the keeper's word first) |
| 47 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/electrum-envelope-key-detection-go-sdk.md](./electrum-envelope-key-detection-go-sdk.md) | ElectrumDecrypt decides whether an envelope embeds the sender's key by its length alone, so a no-key envelope of 32 plaintext bytes or more, and every uncompressed-key envelope, fails to open (from #109; unfiled; drafted by the filings-older-1110 lane on 2026-11-10; the keeper's word first) |
| 48 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/wallet-http-originator-redirect-go-sdk.md](./wallet-http-originator-redirect-go-sdk.md) | The HTTP wallet substrates send the originator unnormalized and follow redirects, so a wallet sees another originator than the TypeScript client's and a call can be replayed to another host (from #323; beside go-sdk #399; unfiled; drafted by the filings-older-1110 lane on 2026-11-10; the keeper's word first) |
| 49 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/auth-transport-redirects-go-sdk.md](./auth-transport-redirects-go-sdk.md) | SimplifiedHTTPTransport follows redirects, so an authenticated message and its signed headers are replayed to whatever host the server names (from #320; unfiled; drafted by the filings-older-1110 lane on 2026-11-10; the keeper's word first) |
| 50 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/local-kvstore-token-authentication-go-sdk.md](./local-kvstore-token-authentication-go-sdk.md) | LocalKVStore writes an unsigned one-field token that the TypeScript LocalKVStore refuses, and reads or spends any basket output as a token without authenticating it (from #326, #341, #454; unfiled; drafted by the filings-older-1110 lane on 2026-11-10; the keeper's word first) |
| 51 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/ecies-bitcore-short-input-go-sdk.md](./ecies-bitcore-short-input-go-sdk.md) | BitcoreDecrypt slices its input without a length check and panics on an envelope shorter than 65 bytes (from #333; the bounds held as a stated row, the panic alone asked; unfiled; drafted by the filings-older-1110 lane on 2026-11-10; the keeper's word first) |
| 52 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/wire-result-validation-go-sdk.md](./wire-result-validation-go-sdk.md) | WalletWireTransceiver returns a wallet's answer without checking it against the request, so a result the reference's client refuses reaches the caller (from #487; beside go-sdk #400, #405, #406; unfiled; drafted by the filings-older-1110 lane on 2026-11-10; the keeper's word first) |
| 53 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/registry-token-fields-go-sdk.md](./registry-token-fields-go-sdk.md) | RegistryClient locks a definition token with forSelf false and reads 6/6/7 fields, so it refuses the reference's tokens and its own, and the reference refuses go-sdk's (from #543 and the registry clause of #544; unfiled; drafted by the filings-older-1110 lane on 2026-11-10; the keeper's word first) |
| 54 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/registry-unlock-input-index-go-sdk.md](./registry-unlock-input-index-go-sdk.md) | RegistryClient revokes and updates a definition by signing the token's output index as the input index, so the spend is signed for the wrong input whenever the two differ (from #548; unfiled; drafted by the filings-older-1110 lane on 2026-11-10; the keeper's word first) |
| 55 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/arithmetic-range-error-verdict-ts-stack.md](./arithmetic-range-error-verdict-ts-stack.md) | Spend lets a RangeError escape validate() and Transaction.verify() on an arithmetic result past V8's string limit, instead of returning a verdict (from #331 and #374; beside ts-stack #1525; unfiled; drafted by the filings-older-1110 lane on 2026-11-10; the keeper's word first) |
| 56 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/auth-http-certificate-request-ts-stack.md](./auth-http-certificate-request-ts-stack.md) | SimplifiedFetchTransport maps a certificateRequest response without initialNonce, which the same SDK's Peer intake then refuses, so a server's HTTP certificate request never reaches its handler (from #416; unfiled; drafted by the filings-older-1110 lane on 2026-11-10; the keeper's word first) |
| 57 | bsv-blockchain/BRCs | [docs/lanes/375-filings/signed-header-comparator-brcs.md](./signed-header-comparator-brcs.md) | BRC-104: name the comparator for the signed headers' "lexicographic" order (code points, or a locale collation) (from #369 and #448; the keeper settles whether to file and which reading to propose; unfiled; drafted by the filings-older-1110 lane on 2026-11-10; the keeper's word first) |
| 58 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/merkle-path-writer-unframed-states-ts-stack.md](./merkle-path-writer-unframed-states-ts-stack.md) | MerklePath.toBinary writes a hashless leaf, a hash of the wrong length, a duplicate's hash or txid flag and a 256-level path as bytes no reader reads back as the path written (from #817, the five refused states in one draft, a section each; unfiled; drafted by the fix-817-merkle-writers lane on 2026-11-09; the keeper's word first) |
| 59 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/merkle-path-writer-txid-false-ts-stack.md](./merkle-path-writer-txid-false-ts-stack.md) | MerklePath.toBinary writes a leaf with txid: false as a txid leaf (from #817's recording, `explicit_txid_false`; unfiled; drafted by the fix-817-merkle-writers lane on 2026-11-09; the keeper's word first) |
| 60 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/beef-make-txid-only-stale-index-ts-stack.md](./beef-make-txid-only-stale-index-ts-stack.md) | Beef.makeTxidOnly does not synchronize nested edits, so after findTxid(A).tx is edited to A' it replaces A' with A alone, the edited transaction lost (unfiled; drafted by the fix-817-door-sync-fold lane on 2026-11-09 from PR #832's rule read; the keeper files it) |
| 61 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/beef-bump-map-history-ts-stack.md](./beef-bump-map-history-ts-stack.md) | Beef's txid-to-BUMP map answers by which doors ran: `indexBumpTxids` after a combine overwrites a txid a later BUMP holds, and the map's own rebuild disagrees with it (from #817's seven stated BUMP cells; unfiled; drafted by the fix-817-edit-door lane on 2026-11-10; the keeper's word first) |
| 62 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/beef-hand-edit-stale-index-ts-stack.md](./beef-hand-edit-stale-index-ts-stack.md) | Beef's txid index is never rebuilt after a hand edit of `txs`: a dropped entry still found, a pushed one stored twice, a swap then `mergeRawTx` overwriting another entry (from #817's four stated hand-edit cells; unfiled; drafted by the review-rule-fix-817-door-sync-rebuild read on 2026-11-10; the keeper's word first) |
| 63 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/beef-writer-unframed-states-ts-stack.md](./beef-writer-unframed-states-ts-stack.md) | Beef.toBinary writes a version word its own reader refuses, a txid-only txid of other than 64 hex digits and a raw entry mergeRawTx kept with bytes after its lock time (or any bytes, with an index) as frames no reader reads back as written (from #817, three states in one draft, a section each; unfiled; drafted by the fix-817-beef-writers lane on 2026-11-10; the keeper's word first) |


The keeper's 2026-10-30 11:1xZ word inserts the certificate-response
preimage witness tenth, after the DER witness. The queue now has seventeen
entries; the new draft starts with `keeper's word first` and awaits its own
per-draft word, then the owner's cadence. The sixteen earlier FILE decisions
stand in their shifted positions. Nothing has been filed.

The keeper's word of 2026-10-31 06:1xZ, [on PR #538](https://github.com/Calhooon/bsv-rs/pull/538#issuecomment-6539950425),
adds an eighteenth draft, FILE, eighteenth in the keeper's order: the
reference's `Point.fromDER` keeps an unreduced coordinate and `encode`
writes it back, so `04`+x+(p+1) is written as `02`+x, the negation of the
point it computed with (the ask: reduce or refuse at parse, and serialize
the point computed with). The queue now has eighteen entries, pending the
owner's cadence word. Nothing has been filed.

The owner's word of 2026-10-31 16:2xZ, relayed by the keeper at 16:3xZ, is
cadence (b). The first six drafts (third to eighth in the keeper's order) were
filed under the owner's name on 2026-10-31 from the drafts as they stood on
beta, the internal provenance lines dropped and a census pointer added (and,
in go-sdk#397, the BRC-reading line's closing sentence addressed to the
keeper); each row above carries its number. The four of 2026-11-01 (rows 1,
2, 11 and 12: go-sdk#399, go-sdk#400, ts-stack#1463, ts-stack#1464) were filed
the same way, and ts-stack#1463 and #1464 also omit their drafts' line
"Existing related filing(s): go-sdk #387. Keep these numbers; confirm their
scope before opening a duplicate." The four of 2026-11-02 (rows 9, 10, 13 and
18: go-sdk#401, go-sdk#402, ts-stack#1466, ts-stack#1467) were filed at 00:00Z
by the keeper's detached script from the drafts as they stood on beta. The
eleven remaining (rows 14 to 17 and 19 to 25: go-sdk#403 to go-sdk#410 for rows
14 to 17 and 19 to 22, ts-stack#1469 and ts-stack#1470 for rows 23 and 24,
go-sdk#411 for row 25) were filed at 13:2xZ on 2026-11-02 under the owner's
name, on the owner's word of that hour through the keeper, as one batch from
the drafts as they stood on beta (the keeper's record
filings-20261102-batch.txt on the stack). Rows 1 and 2 were neither deferred nor dropped: the owner's cadence put the six verifier rows first by consequence; rows 1 and 2 are the first go-sdk pair of 2026-11-01 and rows 11 and 12 ts-stack's (the certificate outpoint bound, the internalize output index width); then two a day per repository in queue order (the keeper, the rulings page's entry of 2026-10-31 17:1xZ).
All twenty-five entries are filed; no row is unfiled. The two-a-day cadence
ended with the batch; from here a new row files the day its draft lands and
is read (the keeper's line).

The keeper's word of 2026-11-01 02:1xZ adds a nineteenth draft, FILE,
nineteenth in the keeper's order: go-sdk PR #392 (the fix of #387, merged
2026-10-30 as `9f4c4a658`) names `decodeOutpoints`' `make(..., 0, count)` from
an unbounded wire count as a hazard it leaves (census row 10). The queue now has
nineteen entries; the new draft is filed on its day of cadence (b), from the
draft as it stands on beta. Nothing new has been filed.

The keeper's word of 2026-11-01 03:1xZ (the rulings page) adds a twentieth
draft, FILE, twentieth in the keeper's order, against go-sdk: the #583 lane
found that go-sdk frames createAction's `noSendChange` (args and result) behind
an outer byte length that BRC-100 and the reference do not write, so a Go
wallet and a TypeScript client refuse each other's list. It is go-sdk's
divergence from the wire, not a stated row. The queue now has twenty entries;
the new draft is filed in the go-sdk pairs' turn of cadence (b), from the draft
as it stands on beta. Nothing new has been filed.

The keeper's word of 2026-11-01 04:1xZ (the rulings page) adds a twenty-first
draft, FILE, against go-sdk, filed ahead of row 20 in the go-sdk turn: go-sdk's
`readTxidSliceWithStatus` sizes the createAction and signAction results'
`sendWithResults` from the wire's absent marker (nine `ff`) and panics
(`makeslice: cap out of range`, `status.go:54`) on every reference result that
carries no `sendWithResults`, and its writer writes a nil list as `00` where the
marker is nine `ff` (one field, one issue). The queue now has twenty-one
entries; the new draft is filed in the go-sdk pairs' turn of cadence (b), ahead
of row 20, from the draft as it stands on beta. Nothing new has been filed.

The keeper's words of 2026-11-01 05:1xZ (the rulings page) add a
twenty-second draft, FILE, against go-sdk: go-sdk's `SerializeCreateActionResult`
writes a success byte of its own inside the result frame (`create_action_result.go:15-16`),
and `DeserializeCreateActionResult` expects it (`:58-61`). BRC-100 and the
reference do not write that byte, so go-sdk's own client refuses every reference
createAction result that carries a txid (`response indicates failure: 1`), and
the reference's client reads go-sdk's inner byte as the txid flag. One frame per issue, so a
maintainer's thread stays one fix. Its consequence is the same as row 20's, and
it is filed in the go-sdk turn beside row 20, from the draft as it stands on beta. The same words
ask row 20's evidence line to state its probe method (bytes handed straight
to go-sdk's serializer functions), and it now does. The queue now has
twenty-two entries. Nothing new has been filed.

The keeper's word of 2026-11-02 05:1xZ adds a twenty-third and a
twenty-fourth draft, FILE, against ts-stack, from #628's cold read of
`MerklePath.ts` at `edf6e03` (the vector `tests/vectors/merkle_path_603.json`
recorded from the reference under Node 22): row 23, the constructor's
54-level bound below BRC-74's "max 64" (`MerklePath.ts:198-199`,
`0074.md:51`); row 24, `combine` merging over the receiver's levels alone
(`MerklePath.ts:520`), so a longer path combined into a shorter receiver
climbs to a root other than the one checked. The queue now has twenty-four
entries. Fourteen are filed; ts-stack's seven earlier rows are all filed. The
ten pending are go-sdk's eight (rows 14 to 17 and 19 to 22) and ts-stack's two
(rows 23 and 24). The cadence's order: rows 14 and 15 on 2026-11-03, rows 16
and 17 on 2026-11-04, then rows 19 to 22 (row 21 ahead of row 20), then rows
23 and 24, about 2026-11-07, each from the draft as it stands on beta at
00:00Z on its day. Nothing new has been filed.

The keeper's word of 2026-11-02 08:1xZ adds a twenty-fifth draft, FILE,
against go-sdk, from #637's cold read's probe of `merklepath.go` at
`2ca481c`: row 25, `combineVerified` merging the other path's levels into
the receiver's by index (`merklepath.go:463-467`), so with the longer path
as the receiver `Combine` files the receiver's level-1 nodes under level 0,
returns no error, and the result climbs to `0a1c0549…` against the checked
root `f3e94742…` (the same pair as row 24, `tests/vectors/merkle_path_603.json`).
The queue now has twenty-five entries. Fourteen are filed. The eleven pending
are go-sdk's nine (rows 14 to 17, 19 to 22 and 25) and ts-stack's two (rows
23 and 24). The cadence's order: rows 14 and 15 on 2026-11-03, rows 16 and 17
on 2026-11-04, then rows 19 to 22 (row 21 ahead of row 20), then rows 23 and
24, then row 25, each from the draft as it stands on beta at 00:00Z on its
day. Nothing new has been filed.

The filings-1109 lane (2026-11-09, the owner's question of that day whether the
references need upstream issues) adds rows 30 to 40, eleven drafts, three
against ts-stack and eight against go-sdk, from the divergence rows and parity
notes since 0.9.0-beta.6 and the open pull requests' notes; the table and the
candidates it dropped are in [docs/lanes/filings-1109.md](../filings-1109.md).
Row 29 (`transaction-version-sign-ts-stack.md`, from #418) is carried by the
open PR #812 and is not repeated here; whichever lands second keeps both rows
in order. Each new draft opens with `keeper's word first` and waits for the
keeper's per-draft word, then the owner's cadence. Nothing new has been filed.

The filings-older-1110 lane (2026-11-10) traced the divergence rows older than
0.9.0-beta.6 that still read "filing pending" with no queue row, and adds rows
41 to 57, seventeen drafts: fourteen against go-sdk, two against ts-stack and
one against the BRCs. Twelve of them supersede thirteen short batch-1 drafts
of 2026-10-30 that were never queued (each old file carries a status line
naming its successor), row 56 rewrites its batch-1 file in place, and row 51
takes the one crash the batch-1 `ecies-byte-bounds.md` named in a sentence; the table and the verdicts, with the rows held as stated rows
and the rows found filed, are in [docs/lanes/filings-older-1110.md](../filings-older-1110.md).
Each new draft opens with `keeper's word first` and waits for the keeper's
per-draft word, then the owner's cadence. Nothing new has been filed.

## HOLD

- bsv-blockchain/go-sdk — [hmac-minimal-key](./hmac-minimal-key.md),
  “Use the amended BRC-56 minimal-length ECDH X coordinate for HMAC”. The
  keeper's reason: go-sdk PR #389 was described as in flight, the maintainers'
  own, so a new filing would duplicate it; reviews 2 and 3 also read this as
  outside the charter. The row now points to that PR instead of ts-stack #1369.
  [PR #389](https://github.com/bsv-blockchain/go-sdk/pull/389), “fix(wallet): key HMAC with minimal-length X coordinate
  per BRC-56”, is by **deggen (@sirdeggen)**. GitHub reports **MERGED** at
  2026-10-28 20:39:45Z when checked for this record, in conflict with the
  keeper's “in flight” wording. The merge is after the `2ca481c` pin (v1.7.2)
  and in no release through v1.7.3, so go-sdk diverges at the pin and in its
  releases and conforms on `master`. The keeper's word of 08:1xZ: the hold holds, a filing would ask go-sdk for
  what its master already carries; the row reads fixed on master at `a8159c77`
  after the pin, in no release through v1.7.3, re-read at the monthly recon and
  closed when a release names it; no duplicate is filed.

- bsv-blockchain/go-sdk — [wire-request-frame-cap-go-sdk](./wire-request-frame-cap-go-sdk.md),
  “Bound a complete wallet wire request before transmitting it”. The keeper's word of 08:1xZ: HOLD as a stated row, on the line drawn
  for the certificate byte bounds (a frame cap is the reference's own resource safeguard
  and not a BRC number, Go's choice to make); the row names the difference; this crate's
  processor cap (#505) runs as hardening.

## AMEND (the keeper's 08:1xZ word: FILE, ninth)

- bsv-blockchain/go-sdk — [certificate-bounds-der](./certificate-bounds-der.md),
  “Certificate wallet conversion rewrites valid high-S signature bytes” (the draft as rewritten to its one claim by the DER witness, PR #506 at `8e57ee46`: go-sdk's certificate adapter rewrites a valid high-S signature to low S where the reference and this crate preserve the bytes; the byte bounds a stated row, ours). The
  keeper's reason: byte bounds on the field, frame and keyring entry are the
  reference's safeguards, not BRC numbers, and stay a stated row. File DER
  preservation alone once a round-trip witness shows Go re-serializing the
  certificate's signature bytes (BER parsing and high-S normalization at
  `primitives/ec/signature.go:77-102,297-299`). The sibling
  `fix-375-der-witness` lane owns the draft rewrite, row 60 and its census;
  this queue records the word without changing that work.

  The keeper's word of 08:1xZ on the witness (PR #506): FILE, ninth in the queue, after
  canonical-varint-reader and before the BRC-100 widths; a signed certificate whose bytes
  change through an adapter is a defect a user meets when a certificate crosses SDKs.