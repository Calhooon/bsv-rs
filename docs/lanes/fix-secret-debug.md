# Lane fix-secret-debug: no secret leaves through `Debug` or an error's text (PR #851)

Base: `origin/beta` at `7df16cf6`; the lane's commit `508283f5`; the fold on `lane/fix-secret-debug-fold` from `508283f5`. Reference: `ts-stack@edf6e03` (`packages/sdk/src/compat/Mnemonic.ts`, `compat/HD.ts`, `primitives/PrivateKey.ts`, `primitives/Polynomial.ts`, `primitives/BigNumber.ts`); Go: `go-sdk@2ca481c` (`compat/bip39/bip39.go`). The program's record of this subject is the API audit's C-DEBUG row (the issue #843 thread); the PR names no issue of its own.

## The invariant

A secret leaves this crate only through a door a caller names: `PrivateKey::to_wif`, `to_wif_with_prefix`, `to_hex`, `to_bytes`; `KeyShares::to_backup_format`; `PointInFiniteField::to_point_string`; `Mnemonic::phrase`; the `Display` of a `Mnemonic` (the phrase) or of an `ExtendedKey` (the xprv for a private key). Each door's rustdoc says it reveals the secret (the rule read's commit `41ce1e0b` for the first six; the two `Display` impls moved beside their `Debug` and documented by the fold, `src/compat/bip39/redact.rs`, `src/compat/bip32_format.rs`, since `mnemonic.rs` and `bip32.rs` sit at their ratchet ceilings). Never through `Debug`; never through an error's text: for the types and doors the two tests enumerate, save the ECDH shared secret returned as a `PublicKey` (this record's rows after the cut; the rule read of the fold).

## Sweep one: `Debug`

The lane's sweep (`508283f5`): every type holding secret material, its `{:?}` run.

| Type | Printed before | After |
|---|---|---|
| `Mnemonic` | derived: every word | `Mnemonic(<redacted, 12 words, English>)` |
| `KeyShares` | derived: each share's `y` hex | share count, threshold, integrity tag |
| `PointInFiniteField` | derived: `y` hex | `x` and `y: <redacted>` |
| `Polynomial` | derived: the points | point count, threshold |
| `PrivateKey`, `P256PrivateKey`, `ExtendedKey`, `SymmetricKey`, `KeyDeriver`, `CachedKeyDeriver`, `ProtoWallet` | already hand-written, redacted | pinned |
| `HmacDrbg` | no `Debug` | none |

The fold's sweep (the rule read's finding): the fields a grep marks as credentials and the types holding them. Command: `grep -rn -B1 "^\s*pub\(([a-z]*)\)\? \?\(headers\|api_key\|auth_token\|token\|password\|bearer\|credential[s]*\)\s*:" src --include='*.rs'` (11 fields), then `grep -rni authorization src --include='*.rs'` (14 lines: the six senders and the four header shapes' comments and filters).

| Type | Field | Printed before | After |
|---|---|---|---|
| `ArcConfig` | `api_key` | derived: `Some("<key>")` | `Some(<redacted>)` / `None` (`src/transaction/credential_debug.rs`) |
| `TeranodeConfig` | `api_key` | the same | the same |
| `WocBroadcastConfig` | `api_key` | the same | the same |
| `LivePolicyConfig` | `api_key` | the same | the same |
| `BlockHeadersServiceConfig` | `auth_token` | the same | the same |
| `auth::transports::http::HttpRequest`, `HttpResponse` | `headers: Vec<(String, String)>` | derived: an `authorization` value | `<redacted>` under `authorization` in any case (`src/auth/header_debug.rs`) |
| `auth::AuthFetchOptions`, `auth::Response` | `headers: IndexMap<String, String>` | the same | the same |
| `ArcBroadcaster`, `TeranodeBroadcaster`, `WhatsOnChainBroadcaster`, `LivePolicy`, `BlockHeadersServiceTracker` | `config` | no `Debug` | none (nothing to redact) |
| `KVStoreEntry`, `KVStoreQuery`, `KVStoreContext`, `KVStoreFields`, `AuthenticatedToken`, `RegistryRecord` | `key`, `token` | derived | kept: a key name, an on-chain token (the rule's `ALLOWED`) |

No public field changed its type or its name; dependents build these configurations by literal.

## Sweep two: error texts

Command: `grep -rnE "pub fn (from_[a-z_]+|parse[a-z_]*)\(" src/primitives/ec/private_key.rs src/primitives/symmetric.rs src/primitives/p256.rs src/compat/bip32.rs src/compat/bip39/mnemonic.rs src/primitives/bsv/shamir.rs src/primitives/bsv/polynomial.rs src/totp/*.rs` gives 19 lines (`/Volumes/Lanes/out/bsv-rs/fix-secret-debug-fold/doors_grep.txt`); five read public material (`P256PublicKey::from_bytes`, `from_hex`; `P256Signature::from_der`, `from_compact`, `from_compact_slice`); TOTP takes its secret as bytes and parses none. The fifteen doors: `PrivateKey::from_hex`, `from_wif`, `from_bytes`; `P256PrivateKey::from_hex`, `from_bytes`; `SymmetricKey::from_bytes`; `ExtendedKey::from_string`; `Mnemonic::from_phrase`, `from_phrase_with_language` (all nine languages), `from_binary`, `from_entropy`, `from_entropy_with_language`; `KeyShares::from_backup_format`; `PointInFiniteField::from_string`.

Each is fed six malformed forms of a real secret (one character changed, dropped, added out of and in its alphabet, a separator moved or two characters swapped, truncated, doubled; for bytes the same plus all `0xff`). The bound: no error's `Display`, `Debug` or `{:#?}` carries a run of more than three characters of the secret's text (hex either case, WIF, xprv, phrase, words, a share's `y` in base58, the malformed input itself), a byte list's decimal form read in runs of three elements. Three is the one character and its position the cold read saw (`Invalid character 'z' at position 31`), with room for an error's own words meeting the input by chance (a length's digits); four would let a whole four-letter BIP-39 word through, and each English word is fixed by its first four letters.

On `508283f5` two doors were over the bound, both older than the PR: `KeyShares::from_backup_format` (`decode_share`: `Invalid share format: expected 'base58(x).base58(y).threshold.integrity', got '<share>'` for other than four parts; its threshold `Invalid threshold in share: <text> (<error>)`) and `PointInFiniteField::from_string` (`Invalid point string format: expected 'base58(x).base58(y)', got '<text>'`). The fold takes the reference's words, which carry nothing of the share: `Invalid share format in share <idx>. Expected format: "x.y.t.i"` (`PrivateKey.ts:74`), `Invalid canonical share data in share <idx>` (`:87`), `Finite-field point must use a bounded canonical Base58 representation` (`Polynomial.ts:32-45`). Every other door names at most one character and its position, a length, a checksum or a version byte.

## The rule

`tests/arch_secret_debug.rs`, lexical. Widened by the fold: derives joined across lines and read inside `cfg_attr(.., derive(..))`, other attributes (multi-line ones too) and comments skipped between derive and type; every visibility; the field list extended (`api_key`, `auth_token`, `token`, `phrase`, `private_key`, `privkey`, `private_key_cache`, `symmetric_key_cache`, `share`, `shares`, and the common `key` and `y`); an `ALLOWED` of eight reviewed types with their reasons, a stale entry refused. What it cannot see, stated in its header: a tuple struct is read by its name alone (`struct Material(pub [u8; 32])` passes); a field whose name says nothing (`bytes`, `inner`); a type a macro defines; and a hand-written `Debug` that prints a secret, caught only for the types `tests/secret_debug.rs` formats.

## RED

- On `7df16cf6` with the PR's tests: 4 of 9 (`Mnemonic { words: ["xxxxx", ...], language: English }`, `KeyShares ... y: BigNumber(xxxx...)`, `invalid word in mnemonic: xxxxxx`, the holder); the rule naming `Mnemonic`, `PointInFiniteField`, `Polynomial`, `KeyShares`.
- On `508283f5` with the fold's two files (a `git archive` scratch, its own target dir; `/Volumes/Lanes/out/bsv-rs/fix-secret-debug-fold/red_508283f5.log`): `secret_debug` 8 of 17 RED: `ArcConfig: Debug carries the credential: ArcConfig { url: "https://arc.taal.com", api_key: Some("xxxx"), timeout_ms: 30000 }` and the other four configurations, `HttpRequest: Debug carries the credential`, `KeyShares::from_backup_format (doubled): its error carries 4 characters of the input` and `PointInFiniteField::from_string (doubled)`, the share words; `arch_secret_debug` naming `src/transaction/broadcasters/arc.rs:293: ArcConfig derives Debug (field api_key)` and the other four.
- `508283f5`'s reader on the six planted types (`red_plants_old_reader.log`): `not caught: ["Wallet", "Holder", "Seeded", "SecretBytes", "Material", "Config"]`.

## Not this lane's (the reads' rows, after the cut)

- The ECDH shared secret is returned as a `PublicKey`, whose `Debug` prints it (`PrivateKey::derive_shared_secret`): a public signature, with #843's API break.
- No zeroize on drop for `Mnemonic`, `ExtendedKey`, `KeyShares`, `PointInFiniteField`.
- `SymmetricKey`'s `fill(0)` on drop, which a compiler may remove.
- `PointInFiniteField`'s derived `PartialEq` in non-constant time.
- `EncryptArgs.plaintext` and `DecryptResult.plaintext` derive `Debug`: the caller's own data.

## The fold (the three reads of `508283f5`, 2026-11-10)

The reads: cold MERGE 0.85 (the two share echoes stated as a residue, the rule's five misses, no lane record), rule FIX 0.85 (the five credential configurations; the two `Display` docs), strength FIX 0.85 (the two share echoes). Folded: the readers' docs commits (`3c69f358`, `41ce1e0b`; `dd3d0e67` corrected the same header line as `3c69f358` and was empty after it), the five configurations and the four header shapes, the share errors in the reference's words, the door table, the widened rule, the two `Display` impls moved and documented, this record. The cold read's residue sentence is rewritten: the share errors are fixed, not stated.

## The second fold (the two scoped re-reads of `0cfef352`, 2026-11-10)

The reads: cold MERGE 0.85 with its docs commit `25487fd8` (the share reader's older differences, stated; now Calhooon/bsv-rs#854, filed, blocks-cut), rule FIX then ACCEPT 0.85 after its docs commit `233ea434` (the invariant scoped to what the tests enumerate, the ECDH exception; the arch header's five blind spots). Both taken, cold then rule; one conflict, the root `CLAUDE.md` row, where the rule read's two insertions (the ECDH exception, the blind spots) were applied to the cold read's sentence, both true after this fold. The captain's line: the three residuals the cold read scored (a caller's `Cookie`, `Proxy-Authorization` or `X-API-Key`, a server's `Set-Cookie`, 0.3; a config URL with user info or a query, 0.15; `UploadInfo`, 0.1) are one class of the invariant, closed as a class.

- Header values. `src/util/debug_redact.rs` (crate-private, under `transaction`): `HeaderList` and `HeaderMap` print every name and redact every value, save `PUBLIC_HEADERS`, compared ignoring ASCII case: `content-type`, `content-length`, `accept`, and the eight constants of `auth::transports::http::headers` (`VERSION`, `IDENTITY_KEY`, `NONCE`, `YOUR_NONCE`, `SIGNATURE`, `MESSAGE_TYPE`, `REQUEST_ID`, `REQUESTED_CERTIFICATES`), each read where the transport defines it (`src/auth/transports/http.rs:65-82`) and each public on the wire: a protocol version, the sender's identity public key, two session nonces (a nonce authenticates only beside its signature), a signature over the message, its type, a random request id and a requested set of certifier keys and types. The transport's filters admit other `x-bsv-*` names (`general.rs:83`, `response_bounds.rs:102`), but those are a caller's headers with a caller's values, so they are redacted; the BRC-105 payment headers are AuthFetch's, not the transport's, and redacted too. A unit test holds the eight equal to the constants. `HttpRequest.search`, the URL's query, prints `<redacted>` when not empty.
- URLs. `debug_redact::Url` (and `OptionUrl`) reads a `&str` without a dependency and never fails: printable ASCII without `"` or `\`, a scheme, `://`, an authority whose last `@` ends the user info, a host of name characters or a bracketed IPv6 literal, a port of digits; anything else `<unparsed url>`. It prints scheme, host, port and path, `<redacted>@`, `?<redacted>`, `#<redacted>`. A password with an unencoded `/` or `?` makes the authority unreadable and prints nothing, save when the user info has one colon and the password's part before that `/` or `?` is digits alone: the reader then takes the user name as the host and those digits as the port, as a WHATWG parser does, and prints them (`https://user:12/ss@host.invalid/` whole, `https://user:12?ss@host.invalid/` as `https://user:12?<redacted>`; found by the scoped re-read of the second fold, stated). Used by the five configurations' URL fields, `WebSocketTransportOptions` (its derive removed) and `WebSocketTransport`, `AcquireCertificateArgs` (its derive removed; `src/wallet/url_debug.rs`, beside `types.rs` at its ratchet line) and `UploadInfo`. Stated: a credential in the path prints.
- `storage::UploadInfo`: a hand-written `Debug` through both, its unit test `an_upload_info_debug_prints_no_signature_and_no_header_value`.
- The rule. The grep: a scan of `src/` (`/Volumes/Lanes/out/bsv-rs/fix-secret-debug-fold2/scan.py`, its output `/Volumes/Lanes/out/bsv-rs/fix-secret-debug-fold2/scan_derive_debug.txt`) of every struct field whose type is `HashMap<String, String>`, `IndexMap<String, String>` or `Vec<(String, String)>` or whose name ends in `url`/`uri` (64 fields, the certificate field and keyring maps among them, out of the class); of these, on types deriving `Debug`, 25 fields on 14 types, no header-named map but `UploadInfo.required_headers` (the four auth shapes already hand-written). Three now write their `Debug` through the helpers (`WebSocketTransportOptions`, `UploadInfo`, `AcquireCertificateArgs`); eleven are `ALLOWED` as published-record URLs or content addresses (`ContactRecord`, `DisplayableIdentity`, `Contact`, `CertifierInfo`, `IdentityCertifier`, `ServiceMetadata`, the three registry definitions, `UploadFileResult`, `UploadMetadata`). The field list gains `headers`, `required_headers`, `upload_url`, `url`, `uri`, `base_url`, `policy_url`, `storage_url`, `certifier_url`, and a suffix arm (`_url`, `_uri`, `_urls`, `_headers`) catches the name nobody listed. The six `_url`/`_headers` words are also caught by the suffixes (listed for the record, not a separate arm).
- RED (`git archive 0cfef352`, the second fold's two test files and the `UploadInfo` unit test overlaid, target outside the tree and the out folder; logs `red_0cfef352.log`, `red_0cfef352_secret_debug.log`, `red_0cfef352_header_probe.log`, `red_arch_plants.log` under `/Volumes/Lanes/out/bsv-rs/fix-secret-debug-fold2/`): `secret_debug` 4 of 20 (the configurations' URL, `AcquireCertificateArgs`, `WebSocketTransportOptions`, the header test at `HttpRequest`'s `search`); the probe on the base, each of the seven names in three cases: `Authorization` redacted, every other value `PRINTS`; the rule naming `WebSocketTransportOptions`, `UploadInfo`, `AcquireCertificateArgs`; the unit test RED (`UploadInfo { .. upload_url: "https://bucket.invalid/obj?X-Amz-Signature=..` caught); on the tip, the suffix arm removed: `not caught: ["callback_url: String", "redirect_uri: String", "mirror_urls: Vec<String>", "response_headers: IndexMap<String, String>"]`; `headers`, `url`, `uri` removed each: its plant not caught.
