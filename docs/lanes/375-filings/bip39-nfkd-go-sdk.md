keeper's word first

# NewSeed hashes the mnemonic and passphrase without NFKD normalization, so a non-ASCII passphrase or phrase seeds other bytes than BIP-39 specifies

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "A BIP-39 phrase is read in NFKD" (#163; "go-sdk@2ca481c normalizes nothing"; "Theirs: go-sdk, filing pending"). Supersedes the short batch-1 draft `bip39-nfkd.md`. Drafted by the filings-older-1110 lane on 2026-11-10.

A go-sdk user who restores a wallet whose passphrase (or phrase) contains a character NFKD changes, such as a full-width or composed Japanese character or an accented Latin letter typed in NFC, derives a different seed, and so different keys, than BIP-39 and every normalizing wallet derive from the same words. The funds are not lost, but the go-sdk wallet shows an empty account for a correct phrase and passphrase.

```go
func NewSeed(mnemonic, password string) []byte {
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+password), 2048, 64, sha512.New)
}
```

The word lookup is a byte compare too (`wordMap[v]`, `bip39.go:130`), so a phrase in another normalization than the list's is refused as an unknown word.

Steps to reproduce (the published BIP-39 Japanese vectors, the passphrase `㍍ガバヴァぱばぐゞちぢ十人十色`; go-sdk read from the code at 2ca481c, not run):

1. Entropy `00000000000000000000000000000000`, the Japanese mnemonic of the linked vector's case 0, that passphrase.
2. BIP-39's seed: `a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55`.
3. `NewSeed` hashes the passphrase's NFC bytes (`㍍` is U+334D, NFKD `メートル`), so its seed is not that one.

Expected: the mnemonic and the passphrase NFKD-normalized before PBKDF2, and the words compared in NFKD, as BIP-39 says.

Actual: the raw bytes hashed and compared.

bsv-rs normalizes the phrase and the passphrase to NFKD since #163 and reads all 24 published Japanese vectors to their seeds.

Witness:

- [tests/compat_bip39_nfkd.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/compat_bip39_nfkd.rs) (`every_japanese_vector_reads_and_seeds_with_its_nfkd_passphrase`, `an_nfd_passphrase_seeds_as_the_nfc_passphrase`, `an_nfd_french_phrase_is_accepted_and_seeds_as_bip39_says`)
- [tests/vectors/bip39_japanese.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/bip39_japanese.json) (24 cases: entropy, mnemonic, passphrase, seed, xprv)

Pinned reference reading:

- [go-sdk@2ca481c59 compat/bip39/bip39.go:253-258](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/compat/bip39/bip39.go#L253-L258) (`NewSeed`) and [:117-131](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/compat/bip39/bip39.go#L117-L131) (the word lookup)

Specification reading: [bitcoin/bips@100ba872 bip-0039.mediawiki:86-87,94-97](https://github.com/bitcoin/bips/blob/100ba872/bip-0039.mediawiki#L86-L97): "The wordlist can contain native characters, but they must be encoded in UTF-8 using Normalization Form Compatibility Decomposition (NFKD)", and the seed's PBKDF2 takes "a mnemonic sentence (in UTF-8 NFKD) used as the password and the string "mnemonic" + passphrase (again in UTF-8 NFKD) used as the salt". The TypeScript reference normalizes both for the seed (`ts-sdk@9e3ede6` `src/compat/Mnemonic.ts:271-272`) and ships English alone.

Existing related filing(s): none found (`--search "BIP39 NFKD"` and `"mnemonic normalization"`, 2026-11-10; #286, closed, is BIP 276).

Requested maintainer action: NFKD-normalize the mnemonic and the passphrase in `NewSeed` and the words before the list lookup, and add the published Japanese vectors as regressions.

Evidence status: BIP-39's seeds are the published vectors, replayed by the linked Rust test; go-sdk source-read at 2ca481c, not run. This draft contains no private-key literal.
